# 免费节点每日聚合

每日自动从多个公开节点源抓取、去重、做存活检测，输出**固定 URL** 的订阅文件。
只需要一个 GitHub 仓库 + 自带 Actions，不需要服务器。

## 订阅地址（把 `USER/REPO` 换成你的）

```
# 1) 最常见格式（v2rayN / Clash Meta / Shadowrocket 通用，base64 编码）
https://raw.githubusercontent.com/USER/REPO/main/output/sub.txt

# 2) mihomo / Clash Verge 用（带分流规则和地区分组）
https://raw.githubusercontent.com/USER/REPO/main/output/mihomo.yaml

# 3) 国内加速（raw 和 jsDelivr 都可能被墙，用 ghproxy 镜像）
https://gh-proxy.com/https://raw.githubusercontent.com/USER/REPO/main/output/sub.txt
https://gh-proxy.com/https://raw.githubusercontent.com/USER/REPO/main/output/mihomo.yaml

# 4) jsDelivr（有 CDN 缓存，更新延迟几分钟到几小时）
https://cdn.jsdelivr.net/gh/USER/REPO@main/output/sub.txt
```

> 优先级建议：**能直连就 raw（即时生效）→ 不通就 gh-proxy → 需要稳定 CDN 就 jsDelivr**。
> 实测在本机环境里 `raw.githubusercontent.com` 和 `cdn.jsdelivr.net` 都不通，
> 只有 `gh-proxy.com` 返回 200，所以国内环境优先用第 3 种。

## 部署步骤

```bash
# 1. 在 GitHub 新建仓库（public，private 也能用但要配置 token 访问 raw）

# 2. 上传本目录内容
git init
git add .
git commit -m "init"
git branch -M main
git remote add origin https://github.com/USER/REPO.git
git push -u origin main

# 3. 手动触发一次，确认 Actions 跑通
#    GitHub → Actions → Daily nodes → Run workflow
```

跑完后 `output/` 下会生成文件并自动提交，订阅地址即可使用。

## 目录结构

```
sources.txt                  ← 节点源清单（改这里增删源）
scripts/aggregate.py         ← 主程序：抓取 → 去重 → 存活检测 → 输出
scripts/parsers.py           ← 各协议 URI / Clash YAML 解析
scripts/validate.py          ← 静态校验（剔除 mihomo 无法解析的节点）
scripts/configgen.py         ← 生成 mihomo 配置（分组 + 分流规则）
output/sub.txt               ← base64 订阅（自动生成）
output/mihomo.yaml           ← mihomo 完整配置（自动生成）
output/nodes.json            ← 节点明细，便于排查（自动生成，不提交）
output/stats.json            ← 本次统计（自动生成）
.github/workflows/daily.yml  ← 每日定时任务
```

## 增删节点源

编辑 `sources.txt`，一行一个 URL，`#` 开头是注释。支持日期占位符：

```
https://example.com/nodes/{Ymd}.txt          → nodes/20261030.txt
https://example.com/{Y}/{m}/{Ymd}.yaml       → 2026/10/20261030.yaml
```

支持的占位符：`{Ymd}` `{ymd}` `{y}` `{Y}` `{m}` `{d}` `{Y}-{m}-{d}` `{Y}/{m}/{d}`

改完 push，workflow 会自动重建（`push` 里监听了 `sources.txt`）。

## 本地运行

```bash
# 完整流程（抓取 + 存活检测）
python3 scripts/aggregate.py

# 跳过存活检测（快，但会混入死节点）
python3 scripts/aggregate.py --skip-check

# 只看前几个源
python3 scripts/aggregate.py --sources /tmp/sub.txt --limit 200
```

常用参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--limit` | 4000 | 最终保留节点上限（按延迟升序） |
| `--concurrency` | 800 | 存活检测并发 |
| `--probe-timeout` | 3.0 | 单节点连接超时（秒） |
| `--workers` | 24 | 源并发抓取数 |
| `--skip-check` | — | 跳过存活检测 |

## 处理流程

```
sources.txt (273 个源)
   ↓ 并发抓取, 单源失败不影响整体
原始文本 (base64 / YAML / URI 列表, 自动识别)
   ↓ 解析成统一节点结构
约 8k~40k 条
   ↓ 协议白名单 (ss ssr vmess vless trojan hysteria2 anytls socks5 http)
   ↓ 全字段去重 (协议+服务器+端口+凭证+传输层参数 的 SHA256)
   ↓ 清洗 + 同一端点归并
   ↓ 静态合法性校验 (validate.py: 假 cipher / 假 REALITY key / 非法 obfs …)
   ↓ TCP 存活检测 (asyncio 并发, 免费源约 95% 是死的)
存活节点 (按延迟升序)
   ↓ 截断到 --limit
   ↓ 名称唯一化 + YAML 特殊字符加引号
output/sub.txt / mihomo.yaml / nodes.json / stats.json
```

## 为什么需要静态校验

mihomo 加载配置是**全有或全无**：`proxies` 里只要有 1 个节点非法，
整份配置就会加载失败，客户端直接报错。

免费源里这类垃圾节点极多，实测遇到的几类：

| 症状 | 原因 |
|---|---|
| `unknown method: ݾ` | ss 的 cipher 是随机乱码 |
| `invalid REALITY short ID` | short-id 不是合法十六进制 |
| `invalid REALITY public key` | public-key 解出来不是 32 字节 |
| `yaml: control characters are not allowed` | 节点名里混了换行/`\x00` |
| `unsupported xtls flow type` | 老式 `xtls-rprx-direct` 已被移除 |

`validate.py` 会在输出前把这些逐条剔掉。

## 验证视角（很重要）

节点存活**取决于从哪台机器去连**。本项目在 GitHub Actions（美国机房）上做真实
HTTPS 验证，所以「通过」代表**从美国出口可用**。

实测同一批节点：

| 验证视角 | 通过率 |
|---|---|
| GitHub Actions（美国机房） | 2016 / 28343 = 7.1% |
| 本机（中国移动） | 4 / 20 抽测 = 20% |

两边不重叠是正常的：美国能连的国内可能被墙，国内能连的美国也可能超时。

如果你主要在国内用，**在本地也跑一遍 `verify_http.py`** 更贴近你的实际网络：

```bash
python3 scripts/aggregate.py --limit 30000        # 抓取 + TCP 粗筛
python3 scripts/verify_http.py --out output --mihomo ./bin/mihomo --keep 1200
python3 scripts/aggregate.py --from-json output/nodes.json --limit 1200
```

## 已知限制

- 已用 mihomo 内核做**真实 HTTPS 握手验证**（`scripts/verify_http.py`），
  不是只看 TCP 通不通。这是必要的：TCP 检测会把 Cloudflare anycast 的节点
  全判为可用（443 端口秒开、延迟 0~1ms），实测 49% 的「存活」里
  真正能握手的只有 7%。
- 验证只测「能否真实访问一个 HTTPS 站点」，不测长期稳定性。
- 免费节点的生命周期通常只有几小时到几天，即使每日更新也可能有大量失效。
- 这些是公开分享的第三方节点，**不要用来登录网银、邮箱等敏感账号**。

## 免责声明

本项目只做公开节点源的自动化汇总，不提供、不托管任何代理服务。
请遵守所在地区的法律法规与目标服务的使用条款。
