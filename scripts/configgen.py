#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_config.py — 把实测存活节点打包成可直接用的 mihomo(clash.meta) 配置
=====================================================================
产出:
  out/mihomo.yaml        完整可用配置 (含 DNS / 规则 / 分组 / 自动测速)
  out/proxies.yaml       只要 proxies 列表 (给其它客户端当 provider 用)
  out/sub_base64.txt     base64 订阅 (v2rayN / Shadowrocket 可直接导入)

特性:
  * 按延迟 + 协议 + 地区分组, 自动生成 URL-Test 最低延迟组
  * 内置常用分流规则 (国内直连 / 国外代理 / 广告拦截)
  * 节点名清洗, 去掉换行与特殊字符, 保证 mihomo 能解析

用法:
  python3 build_config.py -i out/alive.json -o out/mihomo.yaml --top 500
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from collections import defaultdict

# 地区识别: 从节点名里抓国旗 emoji 或国家代码
FLAG_RE = re.compile(
    "[\U0001F1E6-\U0001F1FF]{2}"
)
EMOJI_TO_CODE = {
    "🇭🇰": "HK", "🇹🇼": "TW", "🇯🇵": "JP", "🇰🇷": "KR", "🇸🇬": "SG",
    "🇺🇸": "US", "🇬🇧": "GB", "🇩🇪": "DE", "🇫🇷": "FR", "🇳🇱": "NL",
    "🇷🇺": "RU", "🇨🇦": "CA", "🇦🇺": "AU", "🇮🇳": "IN", "🇹🇷": "TR",
    "🇮🇹": "IT", "🇪🇸": "ES", "🇸🇪": "SE", "🇨🇭": "CH", "🇫🇮": "FI",
    "🇳🇴": "NO", "🇩🇰": "DK", "🇵🇱": "PL", "🇺🇦": "UA", "🇻🇳": "VN",
    "🇹🇭": "TH", "🇲🇾": "MY", "🇮🇩": "ID", "🇵🇭": "PH", "🇧🇷": "BR",
    "🇦🇷": "AR", "🇿🇦": "ZA", "🇦🇪": "AE", "🇮🇱": "IL", "🇮🇪": "IE",
    "🇦🇹": "AT", "🇧🇪": "BE", "🇨🇿": "CZ", "🇭🇺": "HU", "🇷🇴": "RO",
    "🇧🇬": "BG", "🇬🇷": "GR", "🇵🇹": "PT", "🇲🇽": "MX", "🇨🇱": "CL",
    "🇳🇿": "NZ", "🇰🇿": "KZ", "🇸🇦": "SA", "🇪🇬": "EG", "🇳🇬": "NG",
}

# 清洗名字里的换行/引号/逗号等 YAML 敏感字符。
# 注意: 这里也会去掉 "|", 所以 out/mihomo.yaml 里的节点名
# 与 out/alive.json 的原始名**不完全一致** (缺少 | 号)。
# 用 API 切换出口时必须用 mihomo.yaml 里的名字, 否则报
# "Selector update error: proxy not exist"。
NAME_CLEAN = re.compile(r"[\x00-\x1f\x7f\"'\\|,;]")

REGIONS = ["HK", "TW", "JP", "KR", "SG", "US", "GB", "DE", "FR", "NL",
           "CA", "AU", "RU", "other"]


def clean_name(s: str, idx: int) -> str:
    s = (s or "").strip().replace("\n", " ").replace("\r", " ")
    s = NAME_CLEAN.sub("", s)
    s = re.sub(r"\s+", " ", s).strip()
    if not s:
        s = f"node-{idx}"
    return s[:60]


def region_of(name: str) -> str:
    for flag, code in EMOJI_TO_CODE.items():
        if flag in name:
            return code if code in REGIONS else "other"
    up = name.upper()
    for code in REGIONS:
        if code != "other" and re.search(rf"\b{code}\b", up):
            return code
    return "other"


def to_clash_link(n: dict) -> str | None:
    """把节点转回分享 URI, 用于生成 base64 订阅"""
    t = n.get("type")
    name = n["name"]
    if t == "vmess":
        obj = {
            "v": "2", "ps": name, "add": n["server"], "port": str(n["port"]),
            "id": n.get("uuid", ""), "aid": str(n.get("alterId", 0)),
            "scy": n.get("cipher", "auto"), "net": n.get("network", "tcp"),
            "type": "none", "host": "", "path": "", "tls": "tls" if n.get("tls") else "",
            "sni": n.get("servername", "") or n.get("sni", ""),
        }
        ws = n.get("ws-opts") or {}
        if ws:
            obj["path"] = ws.get("path", "/")
            obj["host"] = (ws.get("headers") or {}).get("Host", "")
        return "vmess://" + base64.b64encode(
            json.dumps(obj, ensure_ascii=False).encode()).decode()
    if t == "vless":
        from urllib.parse import urlencode, quote
        q = {"encryption": "none", "type": n.get("network", "tcp"),
             "security": "tls" if n.get("tls") else "none"}
        if n.get("servername"):
            q["sni"] = n["servername"]
        return f"vless://{n.get('uuid','')}@{n['server']}:{n['port']}?{urlencode(q)}#{quote(name)}"
    if t == "trojan":
        from urllib.parse import quote
        return f"trojan://{quote(str(n.get('password','')))}@{n['server']}:{n['port']}#{quote(name)}"
    if t == "ss":
        from urllib.parse import quote
        ui = base64.b64encode(f"{n.get('cipher','')}:{n.get('password','')}".encode()).decode()
        ui = ui.rstrip("=")
        return f"ss://{ui}@{n['server']}:{n['port']}#{quote(name)}"
    if t == "hysteria2":
        from urllib.parse import quote
        return f"hysteria2://{quote(str(n.get('password','')))}@{n['server']}:{n['port']}#{quote(name)}"
    if t == "socks5":
        # 标准 socks URI: socks://base64(user:pass)@host:port
        # 无认证时用 ":" 的 base64 "Og==" (v2rayN / mihomo 都认)
        from urllib.parse import quote
        u, pw = str(n.get("username") or ""), str(n.get("password") or "")
        cred = base64.b64encode(f"{u}:{pw}".encode()).decode().rstrip("=")
        return f"socks://{cred}@{n['server']}:{n['port']}#{quote(name)}"
    if t == "http":
        # http/https 代理没有官方 URI 标准, 但 v2rayN / Shadowrocket /
        # mihomo 都能解析 http://user:pass@host:port 这种写法
        from urllib.parse import quote
        u, pw = str(n.get("username") or ""), str(n.get("password") or "")
        auth = f"{quote(u, safe='')}:{quote(pw, safe='')}@" if (u or pw) else ""
        scheme = "https" if n.get("tls") else "http"
        return f"{scheme}://{auth}{n['server']}:{n['port']}#{quote(name)}"
    if t == "anytls":
        from urllib.parse import quote
        return f"anytls://{quote(str(n.get('password','')))}@{n['server']}:{n['port']}#{quote(name)}"
    return None


def build_yaml(nodes: list[dict], top: int) -> str:
    nodes = nodes[:top] if top else nodes

    # 分配唯一名
    seen: dict[str, int] = {}
    for n in nodes:
        base = clean_name(n.get("name", ""), 0)
        if base.startswith("n0") and len(base) == 7:      # 探针残留名
            base = f"{n['type']} {n['server']}"
        if base in seen:
            seen[base] += 1
            n["_name"] = f"{base} #{seen[base]}"
        else:
            seen[base] = 1
            n["_name"] = base

    by_region: dict[str, list[dict]] = defaultdict(list)
    for n in nodes:
        n["_region"] = region_of(n["_name"])
        by_region[n["_region"]].append(n)

    L: list[str] = []
    L.append("# ============================================================")
    L.append("#  mihomo / Clash.Meta 配置 —— 由 build_config.py 自动生成")
    L.append(f"#  节点数: {len(nodes)}  (全部经过真实 mihomo 连通性实测)")
    L.append("#  用法: mihomo -d . -f mihomo.yaml")
    L.append("# ============================================================")
    L.append("mixed-port: 7890")
    L.append("allow-lan: true")
    L.append("bind-address: '*'")
    L.append("mode: rule")
    L.append("log-level: info")
    L.append("ipv6: false")
    L.append("unified-delay: true")
    L.append("tcp-concurrent: true")
    L.append("find-process-mode: strict")
    L.append("")
    L.append("external-controller: 127.0.0.1:9090")
    L.append("")
    L.append("profile:")
    L.append("  store-selected: true")
    L.append("  store-fake-ip: true")
    L.append("")
    L.append("sniffer:")
    L.append("  enable: true")
    L.append("  sniff:")
    L.append("    HTTP:")
    L.append("      ports: [80, 8080-8880]")
    L.append("      override-destination: true")
    L.append("    TLS:")
    L.append("      ports: [443, 8443]")
    L.append("    QUIC:")
    L.append("      ports: [443, 8443]")
    L.append("")
    L.append("dns:")
    L.append("  enable: true")
    L.append("  listen: 0.0.0.0:1053")
    L.append("  ipv6: false")
    L.append("  enhanced-mode: fake-ip")
    L.append("  fake-ip-range: 198.18.0.1/16")
    L.append("  fake-ip-filter:")
    L.append("    - '*.lan'")
    L.append("    - '*.local'")
    L.append("    - '+.msftconnecttest.com'")
    L.append("    - '+.msftncsi.com'")
    L.append("  default-nameserver: [223.5.5.5, 119.29.29.29, 8.8.8.8]")
    L.append("  nameserver:")
    L.append("    - https://223.5.5.5/dns-query")
    L.append("    - https://1.1.1.1/dns-query")
    L.append("    - https://8.8.8.8/dns-query")
    L.append("  fallback:")
    L.append("    - https://1.0.0.1/dns-query")
    L.append("    - tls://8.8.4.4:853")
    L.append("  fallback-filter:")
    L.append("    geoip: true")
    L.append("    geoip-code: CN")
    L.append("")
    L.append("proxies:")
    for n in nodes:
        p = {k: v for k, v in n.items() if not k.startswith("_")}
        p["name"] = n["_name"]
        L.append("- " + json.dumps(p, ensure_ascii=False))
    L.append("")

    all_names = [n["_name"] for n in nodes]

    def group_names(region: str) -> list[str]:
        return [n["_name"] for n in by_region.get(region, [])]

    L.append("proxy-groups:")
    L.append("- name: " + json.dumps("🚀 节点选择", ensure_ascii=False))
    L.append("  type: select")
    L.append("  proxies:")
    L.append("    - " + json.dumps("♻️ 自动选择", ensure_ascii=False))
    L.append("    - " + json.dumps("DIRECT", ensure_ascii=False))
    for r in REGIONS:
        if group_names(r):
            L.append("    - " + json.dumps(f"🌍 {r}", ensure_ascii=False))

    L.append("- name: " + json.dumps("♻️ 自动选择", ensure_ascii=False))
    L.append("  type: url-test")
    L.append("  url: https://www.gstatic.com/generate_204")
    L.append("  interval: 300")
    L.append("  tolerance: 50")
    L.append("  lazy: true")
    L.append("  proxies:")
    for nm in all_names:
        L.append("    - " + json.dumps(nm, ensure_ascii=False))

    L.append("- name: " + json.dumps("🌏 全部节点", ensure_ascii=False))
    L.append("  type: select")
    L.append("  proxies:")
    for nm in all_names:
        L.append("    - " + json.dumps(nm, ensure_ascii=False))

    for r in REGIONS:
        g = group_names(r)
        if not g:
            continue
        L.append("- name: " + json.dumps(f"🌍 {r}", ensure_ascii=False))
        L.append("  type: url-test")
        L.append("  url: https://www.gstatic.com/generate_204")
        L.append("  interval: 300")
        L.append("  tolerance: 50")
        L.append("  lazy: true")
        L.append("  proxies:")
        for nm in g:
            L.append("    - " + json.dumps(nm, ensure_ascii=False))

    for nm, kw in [("📺 流媒体", ["netflix", "disney", "hbo", "youtube", "nf", "d\\+"]),
                   ("🤖 AI服务", ["us", "jp", "sg", "openai", "gpt"])]:
        members = [n["_name"] for n in nodes
                   if any(re.search(k, n["_name"], re.I) for k in kw)]
        # 空组会让 mihomo 报 "`use` or `proxies` missing" 致命错误,
        # 命中不到就退化成全部节点, 保证配置永远能起来
        if not members:
            members = all_names
        L.append("- name: " + json.dumps(nm, ensure_ascii=False))
        L.append("  type: url-test")
        L.append("  url: https://www.gstatic.com/generate_204")
        L.append("  interval: 300")
        L.append("  tolerance: 50")
        L.append("  lazy: true")
        L.append("  proxies:")
        for m in members:
            L.append("    - " + json.dumps(m, ensure_ascii=False))

    L.append("")
    L.append("rules:")
    # 注意: mihomo 的 rules 是纯字符串, 目标名不能加引号 —— 加了会当成
    # 字面量 "\"REJECT\"" 去找代理从而 fatal。这里直接用裸名。
    rules = [
        "GEOIP,LAN,DIRECT,no-resolve",
        "GEOIP,CN,DIRECT",
        "DOMAIN-SUFFIX,cn,DIRECT",
        "GEOSITE,category-ads-all,REJECT",
        "GEOSITE,openai,🤖 AI服务",
        "GEOSITE,netflix,📺 流媒体",
        "GEOSITE,youtube,📺 流媒体",
        "GEOSITE,disney,📺 流媒体",
        "GEOSITE,geolocation-!cn,🚀 节点选择",
        "MATCH,🚀 节点选择",
    ]
    for r in rules:
        L.append("  - " + r)
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--in", dest="inp", default="out/alive.json")
    ap.add_argument("-o", "--out", dest="out", default="out/mihomo.yaml")
    ap.add_argument("--top", type=int, default=0, help="只取最快的 N 个 (0=全部)")
    ap.add_argument("--proxies-out", default="out/proxies.yaml")
    ap.add_argument("--sub-out", default="out/sub_base64.txt")
    args = ap.parse_args()

    if not os.path.exists(args.inp):
        print(f"[x] 找不到 {args.inp} (先跑 check_nodes.py)", file=sys.stderr)
        return 1
    with open(args.inp, encoding="utf-8") as fh:
        nodes = json.load(fh)
    if not nodes:
        print("[x] 存活节点为空", file=sys.stderr)
        return 1
    print(f"[*] 输入存活节点: {len(nodes)}")

    yml = build_yaml(nodes, args.top)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(yml)
    print(f"[✓] {args.out}")

    # proxies-only provider
    used = nodes[:args.top] if args.top else nodes
    with open(args.proxies_out, "w", encoding="utf-8") as fh:
        fh.write("proxies:\n")
        for n in used:
            p = {k: v for k, v in n.items() if not k.startswith("_")}
            fh.write("- " + json.dumps(p, ensure_ascii=False) + "\n")
    print(f"[✓] {args.proxies_out}")

    # base64 订阅
    links = [x for x in (to_clash_link(n) for n in used) if x]
    blob = base64.b64encode("\n".join(links).encode()).decode()
    with open(args.sub_out, "w", encoding="utf-8") as fh:
        fh.write(blob)
    print(f"[✓] {args.sub_out}  ({len(links)} 条 URI)")

    from collections import Counter
    print(f"[*] 地区分布: {dict(Counter(region_of(clean_name(n.get('name',''),0)) for n in used).most_common())}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
