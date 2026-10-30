#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validate.py — 进内核前的静态合法性校验
========================================
mihomo 加载配置是「全有或全无」: proxies 里只要有 1 个节点非法,
整份配置就加载失败。免费源里垃圾节点极多 (假 cipher、假 REALITY key、
非法 obfs mode …), 所以必须在输出前逐个校验。

下面每条规则都是对着 mihomo 源码 / 实测报错反推出来的,
注释里记录了当时触发的错误原文, 方便以后判断是否仍需要。
"""
from __future__ import annotations

import base64
import re


def proxy_valid(n: dict) -> bool:
    """不依赖 mihomo 的纯静态校验 —— 尽量在进内核前就把废节点剔掉。

    二分是 O(坏节点数 × log n) 次「整批配置解析」, 非常慢。
    免费源里垃圾节点成百上千 (假 cipher、假 key、缺字段),
    不预过滤的话整个流程会被拖死。

    已确认会触发 mihomo 400 的几类:
      * ss cipher 不是受支持算法 (例如 "qo}_" 这种随机串)
      * ss 2022-blake3-* 的 password 不是合法 base64 / 长度不匹配
      * vmess/vless 缺 uuid, trojan/hy2 缺 password
    """
    import base64 as _b64

    SS_CIPHERS = {
        "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
        "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
        "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
        "chacha20-ietf", "chacha20-ietf-poly1305",
        "xchacha20-ietf-poly1305",
        "rc4-md5", "aes-128-ccm", "aes-192-ccm", "aes-256-ccm",
        "aes-128-gcm-siv", "aes-256-gcm-siv",
        "none", "dummy",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    }
    # 别名 -> mihomo 认的名字 (实测 chacha20-poly1305 会被拒)
    SS_ALIAS = {
        "chacha20-poly1305": "chacha20-ietf-poly1305",
        "chacha20": "chacha20-ietf",
        "xchacha20-poly1305": "xchacha20-ietf-poly1305",
    }
    SS2022 = {"2022-blake3-aes-128-gcm": 16,
              "2022-blake3-aes-256-gcm": 32,
              "2022-blake3-chacha20-poly1305": 32}

    t = str(n.get("type", "")).lower()
    cipher = str(n.get("cipher", "")).strip()

    # 只保留本流程能可靠验证的协议。wireguard / tuic / ssh / snell /
    # mieru 等在免费源里几乎全是残废节点(缺 up/down 等必填字段),
    # 混进来只会让整批重载 400, 直接排除。
    SUPPORTED = {"ss", "ssr", "vmess", "vless", "trojan",
                 "hysteria2", "anytls", "socks5", "http"}
    if t not in SUPPORTED:
        return False
    # hysteria v1 需要 up/down 带宽字段, 免费源基本都缺 -> 整批 400
    if t == "hysteria2":
        for f in ("up", "down"):
            if f in n:
                n.pop(f, None)

    if t == "ss":
        if cipher in SS_ALIAS:
            cipher = SS_ALIAS[cipher]
            n["cipher"] = cipher
        if cipher not in SS_CIPHERS:
            return False
        if cipher in SS2022:
            pw = str(n.get("password", ""))
            try:
                raw = _b64.b64decode(pw + "=" * (-len(pw) % 4), validate=False)
            except Exception:  # noqa: BLE001
                return False
            if len(raw) != SS2022[cipher]:
                return False
        # 插件 (obfs / v2ray-plugin) 的模式 mihomo 只认这几种,
        # 免费源里常见 "mode=websocket" 这类非法值, 会让整批 400
        plugin = str(n.get("plugin", "") or "").lower()
        if plugin:
            opts = n.get("plugin-opts") or {}
            mode = str(opts.get("mode", "") or "").lower()
            if plugin == "obfs" and mode not in ("http", "tls"):
                return False
            if plugin == "simple-obfs" and mode not in ("http", "tls"):
                return False
            if plugin == "v2ray-plugin" and mode not in ("websocket", "quic"):
                return False
            if plugin not in ("obfs", "simple-obfs", "v2ray-plugin",
                              "shadow-tls", "restls", "gost-plugin"):
                return False

    if not str(n.get("server", "")).strip() or not n.get("port"):
        return False
    if t in ("vmess", "vless") and not n.get("uuid"):
        return False
    # VLESS flow: mihomo 新版只支持 vision / xtls-rprx-vision,
    # 老式的 xtls-rprx-direct/origin 已被移除, 留着会让整批 400
    if t == "vless" and n.get("flow"):
        if str(n["flow"]).lower() not in ("xtls-rprx-vision", "vision"):
            return False
    # REALITY short-id: 必须是长度 <= 16 的偶数长度十六进制串 (空串允许)。
    # mihomo 对长度/字符集都有硬校验, 免费源里垃圾值很多, 不拦会让整批 400
    ro = n.get("reality-opts")
    if isinstance(ro, dict):
        # short-id 只需满足 REALITY 规范: 十六进制、解码后 <= 8 字节
        # (mihomo 常量 RealityMaxShortIDLen = 8, 源码 adapter/outbound/reality.go)。
        # 注意: 形如 "55e5" / "08" 的值曾经会失败, 但那不是 short-id 的错,
        # 而是 YAML 裸标量被解析成科学计数法/八进制所致 —— 已在 dump_cfg
        # 里通过强制加引号解决, 所以这里不再做过度限制。
        sid = str(ro.get("short-id", "") or "")
        if sid:
            if len(sid) > 16 or len(sid) % 2 != 0:
                return False
            if not all(c in "0123456789abcdefABCDEF" for c in sid):
                return False
        pk = str(ro.get("public-key", "") or "").strip()
        if not pk:
            return False
        # mihomo 要求 public-key 是 **URL-safe base64** (字母表含 - 和 _),
        # 且解码后必须是 32 字节 x25519 公钥。
        # 报错信息 "invalid REALITY public key" / "invalid REALITY short ID"
        # 都可能由它引起, 注意区分。
        pk_norm = pk.replace("+", "-").replace("/", "_").rstrip("=")
        if not re.fullmatch(r"[A-Za-z0-9\-_]+", pk_norm):
            return False
        try:
            raw = _b64.urlsafe_b64decode(pk_norm + "=" * (-len(pk_norm) % 4))
        except Exception:  # noqa: BLE001
            return False
        if len(raw) != 32:
            return False
        ro["public-key"] = pk_norm
    if t in ("trojan", "hysteria2", "hysteria", "anytls") and not n.get("password"):
        return False
    # hysteria2 若声明了 obfs, 必须同时给 obfs-password
    if t == "hysteria2" and n.get("obfs") and not n.get("obfs-password"):
        return False
    if t == "ss" and not n.get("password"):
        return False
    try:
        if not (0 < int(n["port"]) < 65536):
            return False
    except (TypeError, ValueError):
        return False
    return True

def filter_valid(nodes: list[dict]) -> tuple[list[dict], int]:
    """返回 (合法节点, 剔除数)"""
    out = []
    dropped = 0
    for n in nodes:
        if proxy_valid(n):
            out.append(n)
        else:
            dropped += 1
    return out, dropped
