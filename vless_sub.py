#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vless_sub.py — менеджер подписки VLESS.

Скачивает подписку по URL, ищет в ней все vless://-ссылки, показывает список
серверов, просит выбрать один и генерирует конфиг для xray, который слушает
локально как прокси (SOCKS5 127.0.0.1:10808 + HTTP 127.0.0.1:10809).

Зависимости: только requests (уже установлена). Стандартная библиотека для всего остального.

Примеры:
    python3 vless_sub.py https://example.com/sub/xxx
    python3 vless_sub.py https://example.com/sub/xxx -o config.json
    python3 vless_sub.py https://example.com/sub/xxx --socks-port 10810 --http-port 10811
    python3 vless_sub.py https://example.com/sub/xxx --select 2 -o config.json
"""

import argparse
import base64
import json
import re
import sys
from urllib.parse import parse_qsl, unquote, urlparse

import requests

# Браузерный User-Agent чтобы подписки не блокировали скрипт.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

DEFAULT_SOCKS_PORT = 10808
DEFAULT_HTTP_PORT = 10809

LINK_RE = re.compile(r"vless://[^\s<>\"'`]+")


# ---------------------------------------------------------------------------
# Скачивание и декодирование подписки
# ---------------------------------------------------------------------------
def fetch_subscription(url: str, timeout: float) -> str:
    """Скачивает подписку и возвращает её текст."""
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    # requests сам распаковывает gzip/deflate/brotli, если заголовок выставлен.
    return resp.text


def try_decode_subscription(text: str) -> str:
    """
    Подписки обычно лежат в base64 (иногда поверх ещё и URL-encoding).
    Пытаемся получить читаемый текст со ссылками vless://, иначе возвращаем
    исходный текст как есть.
    """
    stripped = text.strip()

    candidates = [text, stripped]
    try:
        candidates.append(unquote(stripped))
    except Exception:
        pass

    # Ссылка прямо в тексте — нечего декодировать.
    for cand in candidates:
        if "vless://" in cand:
            return cand

    # Подберём base64 и проверим, что внутри есть ссылки.
    for variant in (stripped, unquote(stripped)):
        try:
            padded = variant + "=" * (-len(variant) % 4)
            raw = base64.b64decode(padded, validate=False)
            decoded = raw.decode("utf-8", errors="replace")
            if "vless://" in decoded:
                return decoded
        except Exception:
            continue

    return text


def extract_links(text: str) -> list[str]:
    """Достаёт из текста все vless://-ссылки."""
    links = []
    for link in LINK_RE.findall(text):
        link = link.rstrip(".,;)]}'\")")
        if link not in links:
            links.append(link)
    return links


# ---------------------------------------------------------------------------
# Парсинг vless://-ссылки
# ---------------------------------------------------------------------------
def parse_vless(link: str) -> dict | None:
    """
    Разбирает vless://userinfo@host:port?params#remark по формату
    https://github.com/XTLS/Xray-core/discussions/716
    """
    parsed = urlparse(link)
    if parsed.scheme.lower() != "vless":
        return None

    userinfo, _, hostport = parsed.netloc.partition("@")
    if not userinfo or not hostport:
        return None

    host = hostport
    port = 443
    if ":" in hostport:
        host, _, port_str = hostport.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            port = 443

    # parse_qsl сам декодирует percent-encoding (в т.ч. %2F в path).
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    for key in list(params):
        if params[key] == "":
            params.pop(key)

    remark = unquote(parsed.fragment or "")

    return {
        "uuid": userinfo,
        "host": host,
        "port": port,
        "remark": remark,
        "params": params,
    }


# ---------------------------------------------------------------------------
# Описание сервера
# ---------------------------------------------------------------------------
def describe_server(srv: dict) -> str:
    """Однострочное человекочитаемое описание сервера из подписки."""
    params = srv["params"]
    net = params.get("type", "tcp")
    security = params.get("security", "none")
    pieces = [f"{srv['host']}:{srv['port']}", f"net={net}"]

    if security in ("tls", "reality"):
        sni = params.get("sni") or srv["host"]
        pieces.append(f"sec={security}")
        if security == "reality":
            pieces.append(f"sni={sni}")

    flow = params.get("flow")
    if flow:
        pieces.append(f"flow={flow}")

    label = ""
    if srv.get("remark"):
        label = f"  «{srv['remark']}»"
    return "  ".join(pieces) + label


# ---------------------------------------------------------------------------
# Генерация конфига xray
# ---------------------------------------------------------------------------
def build_xray_config(srv: dict, socks_port: int, http_port: int) -> dict:
    """Собирает полный JSON-конфиг xray для выбранного сервера."""
    p = srv["params"]
    network = p.get("type", "tcp")
    security = p.get("security", "none")
    if security not in ("none", "tls", "reality"):
        security = "none"

    user = {"id": srv["uuid"], "encryption": "none"}
    flow = p.get("flow")
    if flow:
        user["flow"] = flow

    stream = {
        "network": network,
        "security": security,
        "sockopt": {"domainStrategy": "UseIP", "tcpFastOpen": True},
    }

    # ---- TLS / Reality ----
    if security == "tls":
        tls = {
            "serverName": p.get("sni") or srv["host"],
            "fingerprint": p.get("fp", "chrome"),
        }
        if p.get("allowInsecure") == "1":
            tls["allowInsecure"] = True
        alpn = p.get("alpn")
        if alpn:
            tls["alpn"] = [x.strip() for x in alpn.split(",") if x.strip()]
        stream["tlsSettings"] = tls

    elif security == "reality":
        # В новых версиях xray (v24+) realitySettings лежит плоско в streamSettings,
        # а не внутри tlsSettings, и для клиента поле называется serverName (не serverNames).
        stream["realitySettings"] = {
            "show": False,
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", "/"),
            "fingerprint": p.get("fp", "chrome"),
            "serverName": p.get("sni") or srv["host"],
        }

    # ---- Транспорт ----
    if network == "ws":
        ws = {}
        if p.get("path"):
            ws["path"] = p["path"]
        if p.get("host"):
            # Современный xray использует wsSettings.host напрямую;
            # headers.Host объявлен deprecated.
            ws["host"] = p["host"]
        stream["wsSettings"] = ws

    elif network == "grpc":
        grpc = {}
        service = p.get("serviceName") or p.get("service")
        if service:
            grpc["serviceName"] = service
        if p.get("mode"):
            grpc["multiMode"] = p["mode"] == "multi"
        stream["grpcSettings"] = grpc

    elif network == "httpupgrade":
        hu = {}
        if p.get("path"):
            hu["path"] = p["path"]
        if p.get("host"):
            hu["host"] = p["host"]
        stream["httpupgradeSettings"] = hu

    elif network == "xhttp":
        xh = {}
        if p.get("path"):
            xh["path"] = p["path"]
        if p.get("host"):
            xh["host"] = p["host"]
        if p.get("mode"):
            xh["mode"] = p["mode"]
        stream["xhttpSettings"] = xh

    elif network == "h2":
        stream["httpSettings"] = {
            "path": p.get("path", ""),
            "host": [p.get("host")] if p.get("host") else [],
        }

    outbound = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": srv["host"],
                    "port": srv["port"],
                    "users": [user],
                }
            ]
        },
        "streamSettings": stream,
    }

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": socks_port,
                "settings": {"udp": True},
            },
            {
                "tag": "http-in",
                "protocol": "http",
                "listen": "127.0.0.1",
                "port": http_port,
                "settings": {},
            },
        ],
        "outbounds": [
            outbound,
            {"tag": "direct", "protocol": "freedom"},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            # Нельзя оставлять правило без полей — xray (>= v24) ругается
            # "this rule has no effective fields". Ловим весь трафик по IP.
            "rules": [
                {"type": "field", "outboundTag": "proxy", "ip": ["0.0.0.0/0", "::/0"]},
            ],
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def choose_server(servers: list[dict], select: int | None) -> dict:
    """Показывает список серверов и просит выбрать один."""
    print(f"Найдено серверов: {len(servers)}\n")
    for i, srv in enumerate(servers, start=1):
        print(f"  [{i:>3}] {describe_server(srv)}")

    if select is not None:
        if 1 <= select <= len(servers):
            print(f"\nВыбран сервер: {select}")
            return servers[select - 1]
        print(f"\nОшибка: --select {select} вне диапазона 1..{len(servers)}",
              file=sys.stderr)
        sys.exit(1)

    print()
    while True:
        try:
            raw = input(f"Выберите номер сервера (1-{len(servers)}) > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nОтменено.", file=sys.stderr)
            sys.exit(1)
        if not raw:
            continue
        try:
            idx = int(raw)
        except ValueError:
            print("   Введите число.\n")
            continue
        if 1 <= idx <= len(servers):
            return servers[idx - 1]
        print(f"   Число должно быть от 1 до {len(servers)}.\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vless_sub.py",
        description="Менеджер подписки VLESS: качает подписку, даёт выбрать сервер "
                    "и генерирует локальный конфиг прокси для xray.",
    )
    parser.add_argument("url", help="URL подписки")
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="сохранить конфиг в файл (по умолчанию — вывод в stdout)",
    )
    parser.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT,
                        help=f"локальный порт SOCKS5 (по умолчанию {DEFAULT_SOCKS_PORT})")
    parser.add_argument("--http-port", type=int, default=DEFAULT_HTTP_PORT,
                        help=f"локальный порт HTTP-прокси (по умолчанию {DEFAULT_HTTP_PORT})")
    parser.add_argument("--select", type=int, metavar="N",
                        help="выбрать сервер по номеру без интерактивного ввода")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="таймаут запроса подписки, секунд (по умолчанию 15)")
    args = parser.parse_args()

    try:
        print(f"Скачиваю подписку: {args.url}")
        content = fetch_subscription(args.url, args.timeout)
    except requests.exceptions.RequestException as exc:
        print(f"Ошибка при загрузке подписки: {exc}", file=sys.stderr)
        sys.exit(1)

    text = try_decode_subscription(content)
    links = extract_links(text)
    if not links:
        print("В подписке не найдено ни одной ссылки vless://.", file=sys.stderr)
        sys.exit(1)

    servers = []
    for link in links:
        srv = parse_vless(link)
        if srv:
            servers.append(srv)
    if not servers:
        print("Не удалось разобрать ни одной ссылки vless://.", file=sys.stderr)
        sys.exit(1)

    srv = choose_server(servers, args.select)

    config = build_xray_config(srv, args.socks_port, args.http_port)
    payload = json.dumps(config, ensure_ascii=False, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"\nКонфиг сохранён в: {args.output}")
    else:
        print("\n----- конфиг для xray -----")
        print(payload)
        print("---------------------------")

    print(
        f"\nИспользование:\n"
        f"  xray run -config <файл>\n"
        f"  SOCKS5: 127.0.0.1:{args.socks_port}\n"
        f"  HTTP:   127.0.0.1:{args.http_port}\n"
    )


if __name__ == "__main__":
    main()