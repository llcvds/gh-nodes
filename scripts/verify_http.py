#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
verify_http.py — 用 mihomo 内核做**真实握手 + HTTP 请求**验证
==============================================================
为什么需要这一步:
    TCP 连通性检测会把 Cloudflare anycast 的节点全部判为可用 ——
    CF 对任意域名的 443 端口都会秒开 TCP (0~1ms),
    但真正发 CONNECT / TLS 时才会暴露节点是死的。

    实测: 只做 TCP 检测时 GitHub Actions 上存活率 49.4%, 中位延迟 1ms;
    加上真实 HTTP 验证后, 存活率会掉到与服务端一致的个位数百分比。

做法:
    1. 生成只含 proxies + 一个 select 组的最小 mihomo 配置 (不需要 geo 数据)
    2. 启动 mihomo, 用 /proxies/{name}/delay 逐个发真实 HTTPS 请求
    3. 只保留真正返回 2xx/3xx 的节点, 回写 output/

依赖: 需要 mihomo 可执行文件, 通过 --mihomo 指定或环境变量 MIHOMO_BIN。
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

GROUP = "VERIFY"
SECRET = "verify-local"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def api(ctrl: str, path: str, timeout: int = 30) -> dict:
    url = f"http://127.0.0.1:{ctrl}{path}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {SECRET}")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


def start_mihomo(binary: str, workdir: str, proxies: list[dict],
                 ctrl: int) -> subprocess.Popen:
    """最小配置: 只有 proxies 和 select 组, 不引用 geo, 避免 CI 里下载数据库"""
    import yaml

    names = [p["name"] for p in proxies]
    cfg = {
        "mixed-port": free_port(),
        "allow-lan": False,
        "mode": "direct",          # 不由内核分流, 全部走组
        "log-level": "silent",
        "ipv6": False,
        "external-controller": f"127.0.0.1:{ctrl}",
        "secret": SECRET,
        "unified-delay": True,
        "tcp-concurrent": True,
        "find-process-mode": "off",
        "profile": {"store-selected": False, "store-fake-ip": False},
        "dns": {"enable": False},
        "proxies": [{k: v for k, v in p.items() if not k.startswith("_")}
                    for p in proxies],
        "proxy-groups": [{"name": GROUP, "type": "select", "proxies": names}],
        "rules": ["MATCH," + GROUP],
    }
    cfg_path = os.path.join(workdir, "config.yaml")
    with open(cfg_path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(cfg, fh, allow_unicode=True, sort_keys=False)
    proc = subprocess.Popen(
        [binary, "-d", workdir, "-f", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    for _ in range(120):
        if proc.poll() is not None:
            raise RuntimeError("mihomo 启动失败 (配置被拒)")
        try:
            api(ctrl, "/version", timeout=2)
            return proc
        except Exception:  # noqa: BLE001
            time.sleep(0.25)
    proc.kill()
    raise RuntimeError("mihomo 启动超时")


def probe(ctrl: str, name: str, url: str, timeout_ms: int) -> int | None:
    q = urllib.parse.urlencode({"url": url, "timeout": timeout_ms})
    path = f"/proxies/{urllib.parse.quote(name, safe='')}/delay?{q}"
    try:
        d = api(ctrl, path, timeout=timeout_ms / 1000 + 8)
        v = d.get("delay")
        return int(v) if v else None
    except Exception:  # noqa: BLE001
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="output", help="输出目录")
    ap.add_argument("--mihomo", default=os.environ.get("MIHOMO_BIN", "mihomo"))
    ap.add_argument("--url", default="https://www.cloudflare.com/cdn-cgi/trace")
    ap.add_argument("--timeout", type=int, default=4000, help="单节点超时(毫秒)")
    ap.add_argument("--workers", type=int, default=200, help="并发探测数")
    ap.add_argument("--batch", type=int, default=1800, help="每批装入内核的节点数")
    ap.add_argument("--keep", type=int, default=1200, help="最终保留数量")
    args = ap.parse_args()

    outdir = Path(args.out)
    nodes_file = outdir / "nodes.json"
    if not nodes_file.exists():
        print(f"[x] 找不到 {nodes_file}", file=sys.stderr)
        return 1
    nodes = json.loads(nodes_file.read_text(encoding="utf-8"))
    print(f"[*] 待验证 {len(nodes)} 个节点, 分 {args.batch} 一批")

    alive: list[dict] = []
    t0 = time.time()
    for i in range(0, len(nodes), args.batch):
        batch = nodes[i:i + args.batch]
        wd = tempfile.mkdtemp(prefix="mihomo-verify-")
        ctrl = free_port()
        proc = None
        try:
            proc = start_mihomo(args.mihomo, wd, batch, ctrl)
            with cf.ThreadPoolExecutor(max_workers=args.workers) as ex:
                futs = {ex.submit(probe, ctrl, n["name"], args.url, args.timeout): n
                        for n in batch}
                for f in cf.as_completed(futs):
                    n = futs[f]
                    d = f.result()
                    if d is not None:
                        alive.append(dict(n, _delay=d))
        except Exception as e:  # noqa: BLE001
            print(f"    [!] 批次失败: {type(e).__name__}: {str(e)[:90]}",
                  file=sys.stderr)
        finally:
            if proc:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except Exception:  # noqa: BLE001
                    proc.kill()
            shutil.rmtree(wd, ignore_errors=True)
        done = min(i + args.batch, len(nodes))
        print(f"    [{done}/{len(nodes)}] 通过 {len(alive)}  "
              f"{time.time()-t0:.0f}s", flush=True)

    print(f"\n[✓] 真实可用 {len(alive)} / {len(nodes)} "
          f"({len(alive)/max(len(nodes),1)*100:.1f}%)  {time.time()-t0:.0f}s")
    if not alive:
        print("[!] 无节点通过真实验证, 保留上一版输出", file=sys.stderr)
        return 0

    alive.sort(key=lambda x: x["_delay"])
    if args.keep and len(alive) > args.keep:
        alive = alive[:args.keep]
        print(f"[*] 截断到最快 {args.keep} 个")

    # 回写 nodes.json, 让后续 configgen 重新生成订阅
    nodes_file.write_text(json.dumps(alive, ensure_ascii=False, indent=1),
                          encoding="utf-8")
    print(f"[✓] 已更新 {nodes_file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
