#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
manage_sources.py — 上游源清单的自动维护
==========================================
两个子功能, 每周跑一次:

  --prune    逐个探测 sources.txt 里的链接, 删掉 404/空响应的死源,
             并把「按日期滚动」的链接改写成占位符形式 (见下)

  --discover 从候选仓库里找出新的可用订阅地址, 追加进 sources.txt

日期占位符 (aggregate.py 运行时会按当天日期展开):
    {Ymd}        → 20261030
    {Y}/{m}/{d}  → 2026/10/30
    {Y}-{m}-{d}  → 2026-10-30
    {Y}/{m}      → 2026/10

所以 https://x.com/uploads/2026/10/20261030.txt
会被改写成 https://x.com/uploads/{Y}/{m}/{Ymd}.txt
以后每天自动指向当天的文件, 不用再改清单。

用法:
    python3 scripts/manage_sources.py --prune
    python3 scripts/manage_sources.py --prune --mirror https://gh-proxy.com/   # 本机被墙时
    python3 scripts/manage_sources.py --discover --limit 150
    python3 scripts/manage_sources.py --prune --discover                       # 两个都跑
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import urllib.parse  # noqa: E402
from parsers import extract_nodes  # noqa: E402

SOURCES = ROOT / "sources.txt"
CANDIDATES = ROOT / "candidates.txt"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# 日期相关正则, 顺序重要 (先匹配更长的组合)
DATE_PATTERNS = [
    (re.compile(r"\d{4}/\d{2}/\d{8}"), "{Y}/{m}/{Ymd}"),
    (re.compile(r"\d{4}/\d{2}/\d{2}"), "{Y}/{m}/{d}"),
    (re.compile(r"\d{4}-\d{2}-\d{2}"), "{Y}-{m}-{d}"),
    (re.compile(r"\d{4}/\d{2}"), "{Y}/{m}"),
    (re.compile(r"\d{8}"), "{Ymd}"),
]

FILE_HINT = re.compile(
    r"(sub|node|clash|v2ray|vmess|vless|trojan|ss|shadow|proxy|config|all|free|airport|订阅|节点)",
    re.I)
GOOD_EXT = (".txt", ".yaml", ".yml", ".json")


# ---------------------------------------------------------------- 通用

def today_date_strings() -> list[str]:
    """今天日期的各种写法, 用来判断 URL 是否为日期滚动链接"""
    t = dt.datetime.now()
    return [t.strftime("%Y%m%d"), t.strftime("%Y-%m-%d"),
            t.strftime("%Y/%m/%d"), t.strftime("%Y/%m"), t.strftime("%y%m%d")]


def normalize_dates(url: str) -> str:
    """把 URL 里出现的今天日期替换成占位符。

    只有**命中今天**才替换 —— 否则会误伤路径里本来就有的数字。
    """
    out = url
    for pat, ph in DATE_PATTERNS:
        def repl(m: re.Match, ph=ph) -> str:
            seg = m.group(0)
            # 该片段必须能解释成今天的日期才替换
            for ds in today_date_strings():
                if seg == ds or seg.replace("-", "").replace("/", "") == ds.replace("-", "").replace("/", ""):
                    return ph
            # %Y/%m/%d 与 %Y/%m 的宽松匹配
            try:
                if ph == "{Y}/{m}/{d}" and seg == dt.datetime.now().strftime("%Y/%m/%d"):
                    return ph
                if ph == "{Y}/{m}" and seg == dt.datetime.now().strftime("%Y/%m"):
                    return ph
            except Exception:  # noqa: BLE001
                pass
            return seg
        out = pat.sub(repl, out)
    return out


def expand(url: str) -> str:
    t = dt.datetime.now()
    rep = {"{Ymd}": t.strftime("%Y%m%d"), "{ymd}": t.strftime("%y%m%d"),
           "{Y}": t.strftime("%Y"), "{y}": t.strftime("%y"),
           "{m}": t.strftime("%m"), "{d}": t.strftime("%d"),
           "{Y}-{m}-{d}": t.strftime("%Y-%m-%d"),
           "{Y}/{m}/{d}": t.strftime("%Y/%m/%d"),
           "{Y}/{m}": t.strftime("%Y/%m")}
    for k in sorted(rep, key=len, reverse=True):
        url = url.replace(k, rep[k])
    return url


MAX_READ = 3 * 1024 * 1024   # 只读前 3MB: 够判断有没有节点, 又不会被大文件拖死


def fetch(url: str, timeout: int = 20) -> tuple[int, str]:
    """注意: 只读前 MAX_READ 字节。

    urllib 的 timeout 是**单次 socket 操作**超时, 不是整个下载的时限,
    所以一个 15MB 的文件在慢速链路上能拖几分钟甚至更久。
    剪掉大文件的尾巴既不影响判断, 又能让整轮探测耗时可预测。
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(MAX_READ)
        return r.status, raw.decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:  # noqa: BLE001
        return 0, ""


def apply_mirror(url: str, mirror: str) -> str:
    """仅对 raw.githubusercontent.com 走镜像 (其它站点镜像不认识)"""
    if mirror and "raw.githubusercontent.com" in url:
        return mirror.rstrip("/") + "/" + url
    return url


NODE_SCHEME = re.compile(
    r"(?:ss|ssr|vmess|vless|trojan|hysteria2?|anytls|socks5?|http)://", re.I)


def count_nodes(text: str) -> int:
    """只做**廉价**的存活判断, 不完整解析。

    一开始这里调的是 parsers.extract_nodes(), 结果 273 个源跑 4 分钟还没完 ——
    3MB 的正文里塞了几万条 URI, 完整解析再 base64 解码, 32 线程把 CPU 打满。
    维护源清单只需要知道「有没有节点」, 用正则扫方案前缀就够了。
    """
    if not text or len(text) < 32:
        return 0
    if NODE_SCHEME.search(text):
        return 1
    if "proxies:" in text[:300000]:
        return 1
    # base64 订阅
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", text[:4096]):
        try:
            dec = base64.b64decode(text + "=" * (-len(text) % 4),
                                   validate=False).decode("utf-8", "ignore")
            if NODE_SCHEME.search(dec) or "proxies:" in dec[:300000]:
                return 1
        except Exception:  # noqa: BLE001
            pass
    return 0


# ---------------------------------------------------------------- prune

def load_urls() -> list[str]:
    if not SOURCES.exists():
        return []
    out = []
    for line in SOURCES.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#") and s.startswith(("http://", "https://")):
            out.append(s)
    return out


def prune(mirror: str, workers: int) -> int:
    urls = load_urls()
    if not urls:
        print("[x] sources.txt 里没有链接", file=sys.stderr)
        return 1
    print(f"[*] 探测 {len(urls)} 个源 (并发 {workers})")

    def check(u: str) -> tuple[str, str, int, int]:
        real = expand(u)
        st, body = fetch(apply_mirror(real, mirror))
        if st == 0:                       # 连接失败/超时: 重试一次
            import time as _t
            _t.sleep(1.5)
            st, body = fetch(apply_mirror(real, mirror))
        if st != 200:
            return u, ("unstable" if st == 0 else "http"), st, 0
        n = count_nodes(body)
        return u, "ok" if n else "empty", st, n

    alive, dead, unstable = [], [], []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for u, kind, st, n in ex.map(check, urls):
            if kind == "ok":
                alive.append((u, n))
            elif kind == "unstable":
                unstable.append(u)
                dead.append((u, st, kind))
            else:
                dead.append((u, st, kind))

    print(f"    可用 {len(alive)}   剔除 {len(dead)}")
    if dead:
        from collections import Counter
        c = Counter(f"HTTP {st}" if k == "http" else "HTTP 200 但无节点"
                    for _, st, k in dead)
        for k, v in c.most_common():
            print(f"      {v:>4}  {k}")

    # 归一化日期 + 去重 (保持原顺序)
    seen, out = set(), []
    for u, _ in alive:
        nu = normalize_dates(u)
        key = expand(nu)
        if key in seen:
            continue
        seen.add(key)
        out.append((nu, u != nu))

    rewritten = sum(1 for _, ch in out if ch)
    ts = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# 上游节点源清单  自动维护: python3 scripts/manage_sources.py --prune",
             f"# 最后探测: {ts}   可用 {len(out)} 个 (已剔除 {len(dead)} 个失效)",
             f"# 日期占位符: {{Ymd}} {{Y}}/{{m}}/{{d}} 等, 运行时按当天展开",
             ""]
    lines += [u for u, _ in out]
    if unstable:
        lines += ["", "# ---- 本次探测连接失败, 暂不启用 (网络/镜像限流所致, 下轮重试) ----"]
        lines += ["# " + u for u in unstable]
    SOURCES.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[✓] sources.txt 已更新: {len(out)} 个源 "
          f"(其中 {rewritten} 个改成了日期占位符)")
    return 0


# ---------------------------------------------------------------- discover

def gh_api(path: str) -> dict | None:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    req = urllib.request.Request("https://api.github.com" + path,
                                headers={"Accept": "application/vnd.github+json",
                                         "User-Agent": UA})
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception:  # noqa: BLE001
        return None


def repo_files(repo: str) -> list[str]:
    """一次 tree 请求拿到仓库全部文件, 返回候选 raw 地址"""
    info = gh_api(f"/repos/{repo}")
    if not info:
        return []
    br = info.get("default_branch") or "main"
    tree = gh_api(f"/repos/{repo}/git/trees/{br}?recursive=1")
    if not tree:
        return []
    out = []
    for it in tree.get("tree", []):
        if it.get("type") != "blob":
            continue
        p = it["path"]
        if not p.lower().endswith(GOOD_EXT):
            continue
        if not FILE_HINT.search(p):
            continue
        if it.get("size", 0) > 12 * 1024 * 1024:
            continue
        out.append(f"https://raw.githubusercontent.com/{repo}/{br}/{p}")
    return out[:12]


def discover(mirror: str, limit: int, workers: int) -> int:
    repos: list[str] = []
    if CANDIDATES.exists():
        for line in CANDIDATES.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                repos.append(s.split("\t")[0])
    # 再用 GitHub 搜索补一些高分仓库
    for q in ("v2ray configs", "free v2ray", "clash nodes", "free proxies"):
        d = gh_api("/search/repositories?q=" + urllib.parse.quote(q)
                   + "&sort=stars&per_page=20")
        for it in (d or {}).get("items", []):
            repos.append(it["full_name"])
    repos = list(dict.fromkeys(repos))
    print(f"[*] 候选仓库 {len(repos)} 个")

    known = {expand(normalize_dates(u)) for u in load_urls()}
    found: list[str] = []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for files in ex.map(repo_files, repos):
            for u in files:
                key = expand(normalize_dates(u))
                if key not in known:
                    known.add(key)
                    found.append(u)
    print(f"    待验证的新地址 {len(found)} 个")
    if not found:
        print("[!] 没有新地址")
        return 0

    def check(u: str):
        st, body = fetch(apply_mirror(u, mirror))
        return u, count_nodes(body) if st == 200 else 0

    good = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        for u, n in ex.map(check, found[:limit * 4]):
            if n > 0:
                good.append((normalize_dates(u), n))
            if len(good) >= limit:
                break
    print(f"    新增可用 {len(good)} 个")
    if not good:
        return 0

    text = SOURCES.read_text(encoding="utf-8").rstrip("\n")
    text += "\n\n# ---- 自动发现 (discover) 新增 ----\n"
    text += "\n".join(u for u, _ in good) + "\n"
    SOURCES.write_text(text, encoding="utf-8")
    print(f"[✓] 已追加到 sources.txt")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--prune", action="store_true")
    ap.add_argument("--discover", action="store_true")
    ap.add_argument("--mirror", default=os.environ.get("SOURCE_MIRROR", ""),
                    help="raw 的镜像前缀, 如 https://gh-proxy.com/ (本机被墙时用)")
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--limit", type=int, default=100, help="discover 最多新增数")
    args = ap.parse_args()
    if not (args.prune or args.discover):
        ap.print_help()
        return 1
    rc = 0
    if args.prune:
        rc |= prune(args.mirror, args.workers)
    if args.discover:
        rc |= discover(args.mirror, args.limit, args.workers)
    return rc


if __name__ == "__main__":
    sys.exit(main())
