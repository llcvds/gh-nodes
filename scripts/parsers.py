#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fetch_nodes.py — 多源节点订阅抓取 / 解析 / 去重 / 清洗
=====================================================
从 linux.do 与 GitHub 社区每日维护的免费节点源拉取订阅，
统一解析成 mihomo(clash.meta) 的 proxies 列表。

支持输入格式:
  * base64 订阅 (v2rayN / shadowrocket 风格)
  * 明文 URI 列表 (ss / ssr / vmess / vless / trojan / hysteria / hysteria2 / anytls / socks / http)
  * Clash / mihomo YAML (proxies: 列表)
  * JSON

关键点: HTTP 类节点只要带 username/password 或 tls 就是 HTTP 代理，不是裸 plain
       —— 这是 subs-check-pro 掉节点的根因之一, 本脚本会原样保留字段。

用法:
  python3 fetch_nodes.py                      # 抓取全部源 -> out/nodes.yaml
  python3 fetch_nodes.py -o out/nodes.yaml -j out/nodes.json
  python3 fetch_nodes.py --only-github        # 只抓 GitHub 源
  python3 fetch_nodes.py --only-linuxdo       # 只抓 linux.do 源
  python3 fetch_nodes.py --no-proxy           # 不走代理直连
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

# --------------------------------------------------------------------------
# 上游订阅源
# --------------------------------------------------------------------------
GITHUB_SOURCES: list[tuple[str, str]] = [
    ("ermaozi_v2ray",   "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/v2ray.txt"),
    ("ermaozi_clash",   "https://cdn.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/clash.yml"),
    ("barryfar_all",    "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/All_Configs_Sub.txt"),
    ("barryfar_vless",  "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/vless.txt"),
    ("barryfar_vmess",  "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/vmess.txt"),
    ("barryfar_trojan", "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/trojan.txt"),
    ("barryfar_ss",     "https://cdn.jsdelivr.net/gh/barry-far/V2ray-Config@main/Splitted-By-Protocol/ss.txt"),
    ("peasoft_nomore",  "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.yml"),
    ("peasoft_meta",    "https://cdn.jsdelivr.net/gh/peasoft/NoMoreWalls@master/list.meta.yml"),
    ("mfuu_v2ray",      "https://cdn.jsdelivr.net/gh/mfuu/v2ray@master/v2ray"),
    ("free18_c",        "https://cdn.jsdelivr.net/gh/free18/v2ray@main/c.yaml"),
    ("free18_t",        "https://cdn.jsdelivr.net/gh/free18/v2ray@main/t.txt"),
    ("mahdibland_ssa",  "https://cdn.jsdelivr.net/gh/mahdibland/ShadowsocksAggregator@master/Eternity.yml"),
    ("anaer_sub",       "https://cdn.jsdelivr.net/gh/anaer/Sub@main/clash.yaml"),
    ("ripao_clash",     "https://cdn.jsdelivr.net/gh/ripaojiedian/freenode@main/clash"),
    ("ripao_sub",       "https://cdn.jsdelivr.net/gh/ripaojiedian/freenode@main/sub"),
    ("vxiaov_clash",    "https://cdn.jsdelivr.net/gh/vxiaov/free_proxies@main/clash/clash.provider.yaml"),
    ("vxiaov_links",    "https://cdn.jsdelivr.net/gh/vxiaov/free_proxies@main/links.txt"),
    ("Pawdroid_sub",    "https://cdn.jsdelivr.net/gh/Pawdroid/Free-servers@main/sub"),
    ("snakem982_meta",  "https://cdn.jsdelivr.net/gh/snakem982/proxypool@main/source/clash-meta-2.yaml"),
    ("snakem982_v2",    "https://cdn.jsdelivr.net/gh/snakem982/proxypool@main/source/v2ray-2.txt"),
    ("Epodonios_all",   "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/All_Configs_base64_Sub.txt"),
    ("Epodonios_vless", "https://cdn.jsdelivr.net/gh/Epodonios/v2ray-configs@main/Splitted-By-Protocol/vless.txt"),
    ("MatinGhanbari",   "https://cdn.jsdelivr.net/gh/MatinGhanbari/v2ray-configs@main/subscriptions/v2ray/super-sub.txt"),
    ("SoliSpirit_all",  "https://cdn.jsdelivr.net/gh/SoliSpirit/v2ray-configs@main/all_configs.txt"),
    ("ALIILAPRO_sub",   "https://cdn.jsdelivr.net/gh/ALIILAPRO/v2rayNG-Config@main/sub.txt"),
    ("MahanKenway_mix", "https://cdn.jsdelivr.net/gh/MahanKenway/Freedom-V2Ray@main/configs/mix.txt"),
    ("0xRadikal_all",   "https://cdn.jsdelivr.net/gh/0xRadikal/Free-v2ray-Configs@main/all/configs.txt"),
    ("ebrasha_all",     "https://cdn.jsdelivr.net/gh/ebrasha/free-v2ray-public-list@main/V2Ray-Config-By-EbraSha-All-Type.txt"),
    ("Au1rxx_verified", "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/all-verified/clash-0001.yaml"),
    ("Au1rxx_clash",    "https://cdn.jsdelivr.net/gh/Au1rxx/free-vpn-subscriptions@main/output/clash.yaml"),
    ("qjlxg_agg",       "https://cdn.jsdelivr.net/gh/qjlxg/aggregator@main/data/clash.yaml"),
    ("Misaka_merge",    "https://cdn.jsdelivr.net/gh/Misaka-blog/chromego_merge@main/sub/merged_proxies_new.yaml"),
    ("Leon406_vless",   "https://cdn.jsdelivr.net/gh/Leon406/SubCrawler@master/sub/share/vless"),
    ("ts-sf_fly",       "https://cdn.jsdelivr.net/gh/ts-sf/fly@main/clash"),
    ("shahid_Router",   "https://cdn.jsdelivr.net/gh/shahidbhutta/Clash@main/Router"),
    ("go4sharing_sub",  "https://cdn.jsdelivr.net/gh/go4sharing/sub@main/sub.yaml"),
    ("WilliamStar007",  "https://cdn.jsdelivr.net/gh/WilliamStar007/ClashX-V2Ray-TopFreeProxy@main/combine/clash.config.yaml"),
    ("mheidari98_all",  "https://cdn.jsdelivr.net/gh/mheidari98/.proxy@main/all"),
    ("AzadNet_txt",     "https://cdn.jsdelivr.net/gh/AzadNetCH/Clash@main/AzadNet.txt"),
    ("Barabama_mix",    "https://cdn.jsdelivr.net/gh/Barabama/FreeNodes@main/nodes/v2rayshare.txt"),
    ("chengaopan_list", "https://cdn.jsdelivr.net/gh/chengaopan/AutoMergePublicNodes@master/list.yml"),
]

# linux.do 社区常用的节点/订阅聚合仓库（论坛帖内长期维护的源）
LINUXDO_SOURCES: list[tuple[str, str]] = [
    ("ld_free_nodes",   "https://cdn.jsdelivr.net/gh/ripaojiedian/freenode@main/clash"),
    ("ld_zhangkai",     "https://cdn.jsdelivr.net/gh/zhangkaiitugithub/passcro@main/speednodes.yaml"),
    ("ld_xiaoji",       "https://cdn.jsdelivr.net/gh/xiaoji235/airport-free@main/v2ray.txt"),
    ("ld_q3dlaXpoaQ1",  "https://cdn.jsdelivr.net/gh/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter@main/APIs/sc1.yaml"),
    ("ld_q3dlaXpoaQ2",  "https://cdn.jsdelivr.net/gh/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter@main/APIs/sc2.yaml"),
    ("ld_q3dlaXpoaQ3",  "https://cdn.jsdelivr.net/gh/Q3dlaXpoaQ/V2rayN_Clash_Node_Getter@main/APIs/sc3.yaml"),
    ("ld_NiceVPN",      "https://cdn.jsdelivr.net/gh/NiceVPN123/NiceVPN@main/utils/pool/output.yaml"),
    ("ld_liMilCo",      "https://cdn.jsdelivr.net/gh/liMilCo/v2r@main/configs.txt"),
    ("ld_sevcator",     "https://cdn.jsdelivr.net/gh/sevcator/5ubscrpt10n@main/mini/m1n1-5ub-14.txt"),
    ("ld_mfbpn",        "https://cdn.jsdelivr.net/gh/mfbpn/tg_mfbpn_sub@main/trial.yaml"),
    ("ld_mgit0001",     "https://cdn.jsdelivr.net/gh/mgit0001/test_clash@main/heima.txt"),
    ("ld_acymz",        "https://cdn.jsdelivr.net/gh/acymz/AutoVPN@main/data/V2.txt"),
    ("ld_PangTouY00",   "https://cdn.jsdelivr.net/gh/PangTouY00/Auto_proxy@main/Long_term_subscription_num"),
    ("ld_peacefish",    "https://cdn.jsdelivr.net/gh/peacefish/nodefree@main/sub/proxy_cf.yaml"),
    ("ld_sakha1370",    "https://cdn.jsdelivr.net/gh/sakha1370/OpenRay@main/output/all_valid_proxies.txt"),
    ("ld_Thordata",     "https://cdn.jsdelivr.net/gh/Thordata/awesome-free-proxy-list@main/proxies/clash/all.yaml"),
]

# 本机已有的订阅服务（那两个给定地址）
LOCAL_SOURCES: list[tuple[str, str]] = [
    ("local_127", "http://127.0.0.1:8299/qAFaAIODQWvM7xazAjfT/download/sub"),
]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# --------------------------------------------------------------------------
# 镜像加速: 本机 cdn.jsdelivr.net 与 raw.githubusercontent.com 不可达,
# 按顺序尝试下列前缀, 命中即可。顺序是按本环境实测可用性排的。
# --------------------------------------------------------------------------
CDN_MIRRORS = [
    "https://fastly.jsdelivr.net/gh/",
    "https://gcore.jsdelivr.net/gh/",
    "https://testingcf.jsdelivr.net/gh/",
    "https://cdn.jsdelivr.net/gh/",
]
GH_MIRRORS = [
    "https://ghproxy.net/",
    "https://gh-proxy.com/",
    "https://ghfast.top/",
    "https://githubdog.com/",
]


def mirror_candidates(url: str) -> list[str]:
    """给定一个原始 URL, 返回 [原地址 + 各种镜像变体]"""
    out = [url]
    if "cdn.jsdelivr.net/gh/" in url:
        tail = url.split("cdn.jsdelivr.net/gh/", 1)[1]
        out = [m + tail for m in CDN_MIRRORS]
    elif "raw.githubusercontent.com/" in url:
        out += [m + url for m in GH_MIRRORS]
    return out

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

# 节点源里大量垃圾/陷阱节点, 过滤掉明显无效的
BAD_SERVER_RE = re.compile(
    r"^(127\.|0\.|10\.|192\.168\.|169\.254\.|1\.0\.0\.|224\.|255\.)"
    r"|^localhost$|^example\.|^invalid$|^your|^none$|^null$|^test",
    re.I,
)


# --------------------------------------------------------------------------
# 工具
# --------------------------------------------------------------------------
def b64pad(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def try_b64decode(text: str) -> str | None:
    raw = text.strip()
    if len(raw) < 16:
        return None
    try:
        out = base64.b64decode(b64pad(raw), validate=False)
        dec = out.decode("utf-8", "ignore")
    except (binascii.Error, ValueError):
        return None
    # 解出来必须像节点列表才算成功
    if re.search(r"(ss|ssr|vmess|vless|trojan|hysteria2?|anytls)://", dec, re.I):
        return dec
    return None


def fetch(url: str, proxy: str | None, timeout: int = 30) -> str | None:
    """按镜像顺序尝试, 任一成功即返回"""
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=SSL_CTX)]
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)

    last_err: Exception | None = None
    for cand in mirror_candidates(url):
        req = urllib.request.Request(cand, headers={
            "User-Agent": UA,
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        try:
            with opener.open(req, timeout=timeout) as r:
                data = r.read()
            if len(data) < 32:
                raise ValueError(f"body too small ({len(data)}B)")
            return data.decode("utf-8", "ignore")
        except Exception as e:  # noqa: BLE001
            last_err = e
            continue
    if last_err is not None:
        print(f"    ! {type(last_err).__name__}: {last_err}", file=sys.stderr)
    return None


def norm_name(name: str) -> str:
    if not name:
        return ""
    return urllib.parse.unquote(name).strip()


# --------------------------------------------------------------------------
# URI 解析器 —— 每个返回 mihomo proxy dict
# --------------------------------------------------------------------------
def _safe_port(v: Any, default: int = 0) -> int:
    try:
        p = int(v)
        return p if 0 < p < 65536 else default
    except (TypeError, ValueError):
        return default


def parse_ss(uri: str, name: str) -> dict | None:
    body = uri[len("ss://"):]
    query = ""
    if "?" in body:
        body, query = body.split("?", 1)
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    name = norm_name(frag) or name

    userinfo = host = None
    if "@" in body:
        userinfo, host = body.rsplit("@", 1)
        if ":" not in userinfo:            # base64(method:pass)
            d = base64.b64decode(b64pad(userinfo), validate=False).decode("utf-8", "ignore")
            userinfo = d
    else:
        # 整段 base64: b64(method:pass@host:port)
        dec = base64.b64decode(b64pad(body), validate=False).decode("utf-8", "ignore")
        if "@" not in dec:
            return None
        userinfo, host = dec.rsplit("@", 1)

    if ":" not in userinfo or not host:
        return None
    method, password = userinfo.split(":", 1)
    # host 可能是 IPv6 [::1]:443
    if host.startswith("["):
        server, _, port = host.rpartition(":")
        server = server.strip("[]")
    else:
        server, _, port = host.rpartition(":")
    p = _safe_port(port)
    if not server or not p:
        return None

    q = urllib.parse.parse_qs(query)
    node: dict[str, Any] = {
        "name": name or f"ss {server}:{p}",
        "type": "ss",
        "server": server,
        "port": p,
        "cipher": method,
        "password": password,
        "udp": True,
    }
    if q.get("plugin"):
        plugin = q["plugin"][0]
        opts = plugin.split(";")
        node["plugin"] = opts[0]
        node["plugin-opts"] = {"mode": opts[1]} if len(opts) > 1 else {}
    return node


def parse_ssr(uri: str, name: str) -> dict | None:
    dec = base64.b64decode(b64pad(uri[len("ssr://"):]), validate=False).decode("utf-8", "ignore")
    parts = dec.split(":")
    if len(parts) < 6:
        return None
    server, port, proto, method, obfs, pwd_b64 = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
    pwd_b64 = pwd_b64.split("/?")[0]
    params = ""
    if "/?" in dec:
        params = dec.split("/?", 1)[1]
    q = urllib.parse.parse_qs(params)
    try:
        password = base64.b64decode(b64pad(pwd_b64), validate=False).decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        password = pwd_b64
    obfsparam = base64.b64decode(b64pad(q.get("obfsparam", [""])[0]), validate=False).decode("utf-8", "ignore") \
        if q.get("obfsparam") else ""
    protoparam = base64.b64decode(b64pad(q.get("protoparam", [""])[0]), validate=False).decode("utf-8", "ignore") \
        if q.get("protoparam") else ""
    remarks = base64.b64decode(b64pad(q.get("remarks", [""])[0]), validate=False).decode("utf-8", "ignore") \
        if q.get("remarks") else ""
    p = _safe_port(port)
    if not server or not p:
        return None
    return {
        "name": norm_name(remarks) or name or f"ssr {server}:{p}",
        "type": "ssr",
        "server": server,
        "port": p,
        "cipher": method,
        "password": password,
        "protocol": proto,
        "obfs": obfs,
        "protocol-param": protoparam,
        "obfs-param": obfsparam,
        "udp": True,
    }


def _v2ray_transport(net: str, q: dict, tls: bool, sni: str) -> dict:
    out: dict[str, Any] = {"network": net or "tcp"}
    if net == "ws":
        out["ws-opts"] = {
            "path": q.get("path", ["/"])[0],
            "headers": {"Host": q.get("host", [sni or ""])[0]},
        }
    elif net in ("h2", "http"):
        out["h2-opts"] = {
            "path": q.get("path", ["/"])[0],
            "host": [q.get("host", [sni or ""])[0]],
        }
    elif net in ("grpc",):
        out["grpc-opts"] = {"grpc-service-name": q.get("serviceName", [""])[0]}
    if tls:
        out["tls"] = True
        if sni:
            out["servername"] = sni
        out["skip-cert-verify"] = True
        if q.get("allowInsecure", ["0"])[0] in ("1", "true"):
            out["skip-cert-verify"] = True
    return out


def parse_vmess(uri: str, name: str) -> dict | None:
    dec = base64.b64decode(b64pad(uri[len("vmess://"):]), validate=False).decode("utf-8", "ignore")
    try:
        j = json.loads(dec)
    except json.JSONDecodeError:
        return None
    server = str(j.get("add", "")).strip()
    p = _safe_port(j.get("port"), 0)
    uid = str(j.get("id", "")).strip()
    if not server or not p or not uid:
        return None
    tls = str(j.get("tls", "")).lower() in ("tls", "true", "1", "reality")
    net = str(j.get("net", "tcp")).lower()
    sni = str(j.get("sni", "") or j.get("host", "") or "")
    q = {"path": [str(j.get("path", "/"))], "host": [str(j.get("host", "") or "")]}
    node: dict[str, Any] = {
        "name": norm_name(str(j.get("ps", ""))) or name or f"vmess {server}:{p}",
        "type": "vmess",
        "server": server,
        "port": p,
        "uuid": uid,
        "alterId": int(j.get("aid", 0) or 0),
        "cipher": str(j.get("scy", "auto") or "auto"),
        "udp": True,
        **_v2ray_transport(net, q, tls, sni),
    }
    return node


def parse_vless(uri: str, name: str) -> dict | None:
    u = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(u.query)
    uid = urllib.parse.unquote(u.username or "")
    if not uid or not u.hostname:
        return None
    p = _safe_port(u.port, 443)
    sec = q.get("security", ["none"])[0]
    sni = q.get("sni", q.get("peer", [""]))[0]
    tls = sec in ("tls", "reality", "xtls")
    node: dict[str, Any] = {
        "name": norm_name(u.fragment) or name or f"vless {u.hostname}:{p}",
        "type": "vless",
        "server": u.hostname,
        "port": p,
        "uuid": uid,
        "udp": True,
        **_v2ray_transport(q.get("type", ["tcp"])[0], q, tls, sni),
    }
    if q.get("flow"):
        node["flow"] = q["flow"][0]
    if sec == "reality":
        node["reality-opts"] = {
            "public-key": q.get("pbk", [""])[0],
            "short-id": q.get("sid", [""])[0],
        }
        node["client-fingerprint"] = q.get("fp", ["chrome"])[0]
    return node


def parse_trojan(uri: str, name: str) -> dict | None:
    u = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(u.query)
    if not u.hostname or not u.username:
        return None
    p = _safe_port(u.port, 443)
    sni = q.get("sni", q.get("peer", [""]))[0]
    node: dict[str, Any] = {
        "name": norm_name(u.fragment) or name or f"trojan {u.hostname}:{p}",
        "type": "trojan",
        "server": u.hostname,
        "port": p,
        "password": urllib.parse.unquote(u.username),
        "udp": True,
        "skip-cert-verify": True,
        **_v2ray_transport(q.get("type", ["tcp"])[0], q, True, sni),
    }
    return node


def parse_hysteria2(uri: str, name: str, typ: str = "hysteria2") -> dict | None:
    u = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(u.query)
    if not u.hostname:
        return None
    p = _safe_port(u.port, 443)
    node: dict[str, Any] = {
        "name": norm_name(u.fragment) or name or f"{typ} {u.hostname}:{p}",
        "type": typ,
        "server": u.hostname,
        "port": p,
        "password": urllib.parse.unquote(u.username or "") or q.get("auth", [""])[0],
        "skip-cert-verify": True,
    }
    if q.get("sni"):
        node["sni"] = q["sni"][0]
    if q.get("obfs"):
        node["obfs"] = q["obfs"][0]
        if q.get("obfs-password"):
            node["obfs-password"] = q["obfs-password"][0]
    if q.get("insecure") in (["1"], ["true"]):
        node["skip-cert-verify"] = True
    if not node["password"]:
        return None
    return node


def parse_anytls(uri: str, name: str) -> dict | None:
    u = urllib.parse.urlparse(uri)
    q = urllib.parse.parse_qs(u.query)
    if not u.hostname:
        return None
    p = _safe_port(u.port, 443)
    node: dict[str, Any] = {
        "name": norm_name(u.fragment) or name or f"anytls {u.hostname}:{p}",
        "type": "anytls",
        "server": u.hostname,
        "port": p,
        "password": urllib.parse.unquote(u.username or ""),
        "client-fingerprint": q.get("fp", ["chrome"])[0],
        "skip-cert-verify": True,
        "udp": True,
    }
    if q.get("sni"):
        node["sni"] = q["sni"][0]
    if not node["password"]:
        return None
    return node


def parse_socks(uri: str, name: str) -> dict | None:
    """socks://base64(b64(user:pass))@host:port  /  socks5://user:pass@host:port"""
    u = urllib.parse.urlparse(uri)
    if not u.hostname:
        return None
    p = _safe_port(u.port, 1080)
    user, pwd = "", ""
    if u.username:
        raw = urllib.parse.unquote(u.username)
        try:
            dec = base64.b64decode(b64pad(raw), validate=False).decode("utf-8", "ignore")
            if ":" in dec:
                user, pwd = dec.split(":", 1)
            else:
                user = dec
        except Exception:  # noqa: BLE001
            user = raw
    if u.password:
        pwd = urllib.parse.unquote(u.password)
    return {
        "name": norm_name(u.fragment) or name or f"socks5 {u.hostname}:{p}",
        "type": "socks5",
        "server": u.hostname,
        "port": p,
        "username": user,
        "password": pwd,
        "udp": True,
    }


def parse_http(uri: str, name: str) -> dict | None:
    u = urllib.parse.urlparse(uri)
    if not u.hostname:
        return None
    p = _safe_port(u.port, 80)
    node: dict[str, Any] = {
        "name": norm_name(u.fragment) or name or f"http {u.hostname}:{p}",
        "type": "http",
        "server": u.hostname,
        "port": p,
        "skip-cert-verify": True,
    }
    if u.username:
        node["username"] = urllib.parse.unquote(u.username)
    if u.password:
        node["password"] = urllib.parse.unquote(u.password)
    if uri.startswith("https://"):
        node["tls"] = True
    return node


PARSERS = {
    "ss": parse_ss,
    "ssr": parse_ssr,
    "vmess": parse_vmess,
    "vless": parse_vless,
    "trojan": parse_trojan,
    "hysteria2": parse_hysteria2,
    "hy2": parse_hysteria2,
    "hysteria": lambda u, n: parse_hysteria2(u, n, "hysteria"),
    "anytls": parse_anytls,
    "socks": parse_socks,
    "socks5": parse_socks,
    "http": parse_http,
    "https": parse_http,
}

URI_RE = re.compile(r"\b(" + "|".join(PARSERS.keys()) + r")://[^\s\"'<>\\]+", re.I)


def parse_uri_list(text: str) -> list[dict]:
    out: list[dict] = []
    for m in URI_RE.finditer(text):
        uri = m.group(0).rstrip(".,;")
        scheme = uri.split("://", 1)[0].lower()
        fn = PARSERS.get(scheme)
        if not fn:
            continue
        try:
            node = fn(uri, "")
        except Exception:  # noqa: BLE001
            node = None
        if node:
            out.append(node)
    return out


def parse_clash_yaml(text: str) -> list[dict]:
    try:
        import yaml
    except ImportError:
        return []
    # 有些 yaml 前面带非 yaml 头, 尝试找到 proxies: 起点
    idx = text.find("proxies:")
    if idx < 0:
        return []
    try:
        doc = yaml.safe_load(text[idx:])
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies") or []
    out: list[dict] = []
    if isinstance(proxies, list):
        for pnode in proxies:
            if isinstance(pnode, dict) and pnode.get("server") and pnode.get("type"):
                pnode.setdefault("name", f"{pnode['type']} {pnode['server']}")
                out.append(pnode)
    return out


def extract_nodes(raw: str, label: str) -> list[dict]:
    """自动判断格式并解析"""
    nodes = parse_clash_yaml(raw)
    if nodes:
        return nodes
    dec = try_b64decode(raw)
    if dec:
        nodes = parse_clash_yaml(dec) or parse_uri_list(dec)
        if nodes:
            return nodes
    return parse_uri_list(raw)


# --------------------------------------------------------------------------
# 清洗 / 去重
# --------------------------------------------------------------------------
def clean(nodes: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    out: list[dict] = []
    for n in nodes:
        srv = str(n.get("server", "")).strip()
        if not srv or BAD_SERVER_RE.search(srv):
            continue
        p = _safe_port(n.get("port"), 0)
        if not p:
            continue
        typ = str(n.get("type", "")).lower()
        if not typ:
            continue
        # 关键: ss/vmess/vless/trojan 等必须有凭证, http/socks 允许匿名
        if typ in ("ss", "ssr") and not n.get("password"):
            continue
        if typ == "vmess" and not n.get("uuid"):
            continue
        if typ == "vless" and not n.get("uuid"):
            continue
        if typ == "trojan" and not n.get("password"):
            continue
        key = (typ, srv, p, str(n.get("uuid") or n.get("password") or n.get("username") or ""))
        if key in seen:
            continue
        seen.add(key)
        n["server"] = srv
        n["port"] = p
        out.append(n)
    return out


def dedupe_names(nodes: list[dict]) -> list[dict]:
    used: dict[str, int] = {}
    for n in nodes:
        base = str(n.get("name") or f"{n['type']} {n['server']}").strip() or "node"
        base = base[:48]
        if base in used:
            used[base] += 1
            n["name"] = f"{base}#{used[base]}"
        else:
            used[base] = 1
            n["name"] = base
    return nodes


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------
def detect_proxy() -> str | None:
    for port, scheme in ((17890, "http"), (7890, "http"), (10808, "http"), (10809, "http")):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.6):
                return f"{scheme}://127.0.0.1:{port}"
        except OSError:
            continue
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="多源节点订阅抓取器")
    ap.add_argument("-o", "--out", default="out/nodes.yaml", help="输出 mihomo yaml")
    ap.add_argument("-j", "--json", default="out/nodes.json", help="输出 json")
    ap.add_argument("--only-github", action="store_true")
    ap.add_argument("--only-linuxdo", action="store_true")
    ap.add_argument("--no-proxy", action="store_true")
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--threads", type=int, default=16)
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    sources: list[tuple[str, str]] = []
    if args.only_github:
        sources = list(GITHUB_SOURCES)
    elif args.only_linuxdo:
        sources = list(LINUXDO_SOURCES)
    else:
        sources = list(GITHUB_SOURCES) + list(LINUXDO_SOURCES) + list(LOCAL_SOURCES)

    proxy = None if args.no_proxy else (args.proxy or detect_proxy())
    print(f"[*] 源数量: {len(sources)}   代理: {proxy or '直连'}   线程: {args.threads}")

    results: dict[str, list[dict]] = {}
    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs = {ex.submit(fetch, url, proxy, args.timeout): (label, url) for label, url in sources}
        for f in as_completed(futs):
            label, url = futs[f]
            raw = f.result()
            if not raw:
                print(f"[x] {label:<18} 拉取失败")
                continue
            nodes = extract_nodes(raw, label)
            results[label] = nodes
            print(f"[+] {label:<18} {len(nodes):>6} 节点  ({len(raw):>8} B)")

    all_nodes: list[dict] = []
    for nodes in results.values():
        all_nodes.extend(nodes)

    print(f"\n[*] 原始合计: {len(all_nodes)}")
    cleaned = clean(all_nodes)
    print(f"[*] 清洗后  : {len(cleaned)}")
    final = dedupe_names(cleaned)

    from collections import Counter
    print("[*] 协议分布:", dict(Counter(n["type"] for n in final).most_common()))

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("# 由 fetch_nodes.py 生成\nproxies:\n")
        for n in final:
            fh.write("- " + json.dumps(n, ensure_ascii=False) + "\n")
    with open(args.json, "w", encoding="utf-8") as fh:
        json.dump(final, fh, ensure_ascii=False, indent=1)
    print(f"[✓] 写入 {args.out}  ({len(final)} 节点)")
    print(f"[✓] 写入 {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
