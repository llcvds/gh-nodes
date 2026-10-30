#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
aggregate.py — 汇总多个免费节点源, 去重 + 存活检测, 输出固定订阅文件
=====================================================================
在 GitHub Actions 上每日运行, 把结果提交回仓库, 于是得到一个固定 URL:

    https://raw.githubusercontent.com/<user>/<repo>/main/output/sub.txt

设计要点
--------
1. 多源抓取: 每个源独立失败, 单源挂了不影响整体 (并发 + 超时 + 重试)。
2. 全字段去重: 按「协议+服务器+端口+凭证+传输层参数」签名,
   只按 name 去重会漏掉同名不同配置的节点 (mihomo 会报 duplicate name)。
3. TCP 存活检测: 用 asyncio 并发连 server:port, 剔掉死节点。
   免费源里 95%+ 是死的, 不筛的话订阅没法用。
4. 名称唯一: 同名追加 #N, 并给含 YAML 特殊字符的名字加引号
   ([OpenRay] xxx 不加引号会被 YAML 当成 flow sequence)。
5. 变更检测: 内容没变就不写文件, 避免 workflow 每天空提交。

用法
----
    python3 scripts/aggregate.py                    # 抓取+检测+输出
    python3 scripts/aggregate.py --skip-check       # 跳过存活检测 (快速)
    python3 scripts/aggregate.py --limit 3000       # 最多保留 3000 个
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from parsers import clean, extract_nodes, fetch  # noqa: E402
from validate import filter_valid  # noqa: E402
import configgen  # noqa: E402

ROOT = HERE.parent
DEFAULT_SOURCES = ROOT / "sources.txt"
OUT = ROOT / "output"

# 协议白名单: 只保留 mihomo 能稳定解析的
KEEP_TYPES = {"ss", "ssr", "vmess", "vless", "trojan",
              "hysteria2", "anytls", "socks5", "http"}

# 去重签名里要排除的字段 (名字、延迟、内部标记)
SIG_SKIP = {"name", "_name", "_delay", "_probe", "_src", "_resolved_ips", "_domain"}


# --------------------------------------------------------------------------
# 源
# --------------------------------------------------------------------------
def load_sources(path: Path) -> list[str]:
    if not path.exists():
        print(f"[x] 找不到源清单 {path}", file=sys.stderr)
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith(("http://", "https://")):
            out.append(expand(s))
    return out


def expand(url: str) -> str:
    """展开日期占位符: {Ymd} {Y} {m} {d} {ymd} {y-m-d} {y-{m}-{d}}"""
    import datetime as dt
    t = dt.datetime.now()
    rep = {
        "{Ymd}": t.strftime("%Y%m%d"),
        "{ymd}": t.strftime("%y%m%d"),
        "{y-m-d}": t.strftime("%Y-%m-%d"),
        "{y_m_d}": t.strftime("%Y_%m_%d"),
        "{Y}-{m}-{d}": t.strftime("%Y-%m-%d"),
        "{Y}/{m}/{d}": t.strftime("%Y/%m/%d"),
        "{Y}": t.strftime("%Y"),
        "{y}": t.strftime("%y"),
        "{m}": t.strftime("%m"),
        "{d}": t.strftime("%d"),
    }
    for k, v in rep.items():
        url = url.replace(k, v)
    return url


def fetch_one(url: str, timeout: int) -> tuple[str, str | None, str]:
    try:
        raw = fetch(url, None, timeout=timeout)
        if not raw:
            return url, None, "空响应"
        return url, raw, ""
    except Exception as e:  # noqa: BLE001
        return url, None, f"{type(e).__name__}: {str(e)[:60]}"


# --------------------------------------------------------------------------
# 去重
# --------------------------------------------------------------------------
def signature(n: dict) -> str:
    """全字段签名 —— 同名但配置不同的节点必须算两个"""
    items = {k: v for k, v in n.items() if k not in SIG_SKIP}
    blob = json.dumps(items, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def dedupe(nodes: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out = []
    for n in nodes:
        sig = signature(n)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(n)
    return out


# --------------------------------------------------------------------------
# 存活检测 (纯 TCP 连接, 不依赖 mihomo)
# --------------------------------------------------------------------------
async def _probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore):
    async with sem:
        t0 = time.monotonic()
        try:
            fut = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            ms = int((time.monotonic() - t0) * 1000)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass
            return ms
        except Exception:  # noqa: BLE001
            return None


async def _probe_all(nodes: list[dict], concurrency: int, timeout: float):
    sem = asyncio.Semaphore(concurrency)
    tasks = [_probe(str(n["server"]), int(n["port"]), timeout, sem) for n in nodes]
    return await asyncio.gather(*tasks)


def tcp_check(nodes: list[dict], concurrency: int = 800, timeout: float = 3.0) -> list[dict]:
    print(f"[*] TCP 存活检测: {len(nodes)} 个节点, 并发 {concurrency}, 超时 {timeout}s")
    t0 = time.time()
    try:
        results = asyncio.run(_probe_all(nodes, concurrency, timeout))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(_probe_all(nodes, concurrency, timeout))
        loop.close()
    alive = []
    for n, ms in zip(nodes, results):
        if ms is not None:
            n["_delay"] = ms
            alive.append(n)
    alive.sort(key=lambda x: x["_delay"])
    el = time.time() - t0
    print(f"[✓] 存活 {len(alive)} / {len(nodes)} ({len(alive)/max(len(nodes),1)*100:.1f}%)  {el:.0f}s")
    return alive


# --------------------------------------------------------------------------
# 名称唯一化 + YAML 引号
# --------------------------------------------------------------------------
YAML_SPECIAL = set("[]{}:,&*!|>'\"%@`#")


def quote_name(s: str) -> str:
    if not s:
        return '""'
    need = s[0] in YAML_SPECIAL or s[-1] in YAML_SPECIAL or ": " in s or " #" in s
    if s.lower() in ("true", "false", "null", "yes", "no", "on", "off"):
        need = True
    if need:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


CTRL_RE = __import__("re").compile(r"[\x00-\x1f\x7f]")


def sanitize_fields(nodes: list[dict]) -> list[dict]:
    """清掉所有字符串字段里的控制字符。

    免费源的节点名里经常混入换行/Tab/\x00 等不可见字符,
    mihomo 读 YAML 时会直接报 "yaml: control characters are not allowed",
    整份配置都加载不了。必须在输出前统一清洗。
    """
    for n in nodes:
        for k, v in list(n.items()):
            if isinstance(v, str):
                nv = CTRL_RE.sub("", v).strip()
                n[k] = nv if nv else v
    return nodes


def unique_names(nodes: list[dict]) -> list[dict]:
    used: dict[str, int] = {}
    for n in nodes:
        base = str(n.get("name") or f"{n.get('type','node')} {n.get('server','')}").strip()
        base = base.replace("\n", " ").replace("\r", " ")[:48] or "node"
        if base in used:
            used[base] += 1
            base = f"{base}#{used[base]}"
        else:
            used[base] = 1
        n["name"] = base
    return nodes


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def write_if_changed(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            if path.read_text(encoding="utf-8") == content:
                return False
        except OSError:
            pass
    path.write_text(content, encoding="utf-8")
    return True


def build_sub_base64(nodes: list[dict]) -> str:
    lines = []
    for n in nodes:
        uri = configgen.to_clash_link(n)
        if uri:
            # 名字统一加引号规则不适用于 URI, 但要 URL 编码
            lines.append(uri)
    raw = "\n".join(lines) + "\n"
    return base64.b64encode(raw.encode()).decode()


def build_mihomo(nodes: list[dict]) -> str:
    # configgen.build_yaml 内部会再分配 _name, 我们先把 name 唯一化好
    return configgen.build_yaml(nodes, 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", default=str(DEFAULT_SOURCES))
    ap.add_argument("--out", default=str(OUT))
    ap.add_argument("--timeout", type=int, default=25, help="单源抓取超时(秒)")
    ap.add_argument("--workers", type=int, default=24, help="并发抓取数")
    ap.add_argument("--skip-check", action="store_true", help="跳过 TCP 存活检测")
    ap.add_argument("--concurrency", type=int, default=800, help="存活检测并发")
    ap.add_argument("--probe-timeout", type=float, default=3.0, help="单节点连接超时(秒)")
    ap.add_argument("--limit", type=int, default=4000, help="最终保留节点上限")
    ap.add_argument("--from-json", default="", help="跳过抓取, 直接用已有 nodes.json 重建输出")
    args = ap.parse_args()

    outdir = Path(args.out)

    # ---- 快速通道: 用已有 nodes.json 重建输出 ----
    if args.from_json:
        nodes = json.loads(Path(args.from_json).read_text(encoding="utf-8"))
        print(f"[*] 从 {args.from_json} 载入 {len(nodes)} 个节点")
        nodes, dropped = filter_valid(nodes)
        if dropped:
            print(f"[*] 静态校验: 剔除 {dropped} 个")
        nodes = unique_names(sanitize_fields(nodes))
        # 源统计沿用上一次的 stats.json (本次没有重新抓取)
        prev = {}
        sf = outdir / "stats.json"
        if sf.exists():
            try:
                prev = json.loads(sf.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                prev = {}
        _write_outputs(outdir, nodes,
                       prev.get("sources_total", 0),
                       prev.get("sources_ok", 0),
                       prev.get("sources_failed", 0))
        return 0

    sources = load_sources(Path(args.sources))
    if not sources:
        print("[x] 源清单为空", file=sys.stderr)
        return 1
    print(f"[*] 源数量: {len(sources)}")

    # ---- 1. 抓取 ----
    t0 = time.time()
    raws: list[tuple[str, str]] = []
    failed = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_one, u, args.timeout): u for u in sources}
        for i, f in enumerate(as_completed(futs), 1):
            url, raw, err = f.result()
            if raw:
                raws.append((url, raw))
                print(f"  [+] {url.split('//',1)[-1][:62]:<64} {len(raw):>9} B")
            else:
                failed += 1
                print(f"  [-] {url.split('//',1)[-1][:62]:<64} {err}")
            if i % 20 == 0:
                print(f"      ...{i}/{len(sources)}")
    print(f"[*] 抓取完成: 成功 {len(raws)} / 失败 {failed}  {time.time()-t0:.0f}s")

    # ---- 2. 解析 ----
    nodes: list[dict] = []
    for url, raw in raws:
        try:
            got = extract_nodes(raw, url)
        except Exception as e:  # noqa: BLE001
            print(f"  [!] 解析失败 {url[:50]}: {type(e).__name__}")
            continue
        nodes.extend(got)
    print(f"[*] 解析出 {len(nodes)} 条")

    # ---- 3. 协议白名单 + 全字段去重 ----
    nodes = [n for n in nodes if str(n.get("type", "")).lower() in KEEP_TYPES]
    before = len(nodes)
    nodes = dedupe(nodes)
    print(f"[*] 全字段去重: {before} -> {len(nodes)}  (剔除 {before-len(nodes)} 个完全重复)")

    # ---- 4. 清洗 + 同一端点归并 ----
    # clean() 会按 (协议, 服务器, 端口, 凭证) 归并: 同一端点的多条配置只留一条。
    # 这一步同时做字段校验 (缺 uuid/password 的丢弃)。
    before = len(nodes)
    nodes = clean(nodes)
    print(f"[*] 清洗+端点归并: {before} -> {len(nodes)}  (剔除 {before-len(nodes)} 个)")
    # ---- 4.5 静态合法性校验 (mihomo 全有或全无, 一个非法整份加载失败) ----
    before = len(nodes)
    nodes, dropped = filter_valid(nodes)
    if dropped:
        print(f"[*] 静态校验: 剔除 {dropped} 个 mihomo 无法解析的节点 -> {len(nodes)}")
    if not nodes:
        print("[x] 无有效节点", file=sys.stderr)
        return 1

    # ---- 5. 存活检测 ----
    if args.skip_check:
        print("[!] 跳过存活检测 (--skip-check), 输出可能包含死节点")
        for n in nodes:
            n.setdefault("_delay", 9999)
    else:
        nodes = tcp_check(nodes, args.concurrency, args.probe_timeout)
        if not nodes:
            print("[!] 本轮存活检测为 0, 保留上一版输出不覆盖 (上游源可能集体失效)",
                  file=sys.stderr)
            return 0

    # ---- 6. 截断 + 唯一名 ----
    if args.limit and len(nodes) > args.limit:
        nodes = nodes[:args.limit]
        print(f"[*] 截断到最快 {args.limit} 个")
    nodes = unique_names(sanitize_fields(nodes))

    # ---- 7. 写出 ----
    _write_outputs(outdir, nodes, len(sources), len(raws), failed)
    return 0


def _write_outputs(outdir: Path, nodes: list[dict],
                   n_sources: int, n_ok: int, n_failed: int) -> None:
    changed = []
    sub = build_sub_base64(nodes)
    if write_if_changed(outdir / "sub.txt", sub):
        changed.append("sub.txt")
    if write_if_changed(outdir / "mihomo.yaml", build_mihomo(nodes)):
        changed.append("mihomo.yaml")
    if write_if_changed(outdir / "nodes.json", json.dumps(nodes, ensure_ascii=False, indent=1)):
        changed.append("nodes.json")

    from collections import Counter
    stats = {
        "updated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "sources_total": n_sources,
        "sources_ok": n_ok,
        "sources_failed": n_failed,
        "nodes_final": len(nodes),
        "protocols": dict(Counter(n["type"] for n in nodes).most_common()),
        "fastest_ms": nodes[0]["_delay"] if nodes else None,
        "median_ms": nodes[len(nodes)//2]["_delay"] if nodes else None,
    }
    if write_if_changed(outdir / "stats.json", json.dumps(stats, ensure_ascii=False, indent=1)):
        changed.append("stats.json")

    print()
    print(f"[✓] 输出 {len(nodes)} 个节点 -> {outdir}")
    print(f"    协议: {stats['protocols']}")
    print(f"    最快 {stats['fastest_ms']}ms  中位 {stats['median_ms']}ms")
    print(f"    变更文件: {', '.join(changed) if changed else '无 (内容未变)'}")


if __name__ == "__main__":
    sys.exit(main())
