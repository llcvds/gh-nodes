#!/bin/bash
# ============================================================
#  在 GitHub 上创建仓库并推送本项目
#  用法:
#      export GITHUB_TOKEN=ghp_xxx        # 需要 repo 权限
#      bash push_to_github.sh [仓库名]
#
#  说明:
#     - 默认仓库名 gh-nodes，private 仓库也能用（raw 需带 token 访问）
#     - 建议 public，订阅链接才能免 token 直接拉取
#     - 重复执行会自动复用已有仓库
# ============================================================
set -euo pipefail

REPO_NAME="${1:-gh-nodes}"
TOKEN="${GITHUB_TOKEN:-}"
API="https://api.github.com"
cd "$(dirname "$0")"

die() { echo "[x] $*" >&2; exit 1; }

[ -n "$TOKEN" ] || die "请先设置 GITHUB_TOKEN 环境变量（需要 repo 权限的 PAT）"

# ---------- 1. 验证 token ----------
echo "[1/6] 验证 token"
USER_JSON=$(curl -sS -m 30 -H "Authorization: Bearer $TOKEN" \
              -H "Accept: application/vnd.github+json" "$API/user" || true)
LOGIN=$(printf '%s' "$USER_JSON" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin); print(d.get('login') or '')
except Exception: print('')")
if [ -z "$LOGIN" ]; then
  echo "$USER_JSON" | head -3
  die "token 无效或无权限（需要 repo scope 的 classic token，或 fine-grained token 勾选 Administration: Read and write）"
fi
echo "      账号: $LOGIN"

# ---------- 2. 创建仓库（已存在则复用） ----------
echo "[2/6] 创建仓库 $LOGIN/$REPO_NAME"
CODE=$(curl -sS -m 40 -o /tmp/_repo.json -w '%{http_code}' \
  -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" "$API/user/repos" \
  -d "$(python3 -c "
import json,sys
print(json.dumps({
  'name': '$REPO_NAME',
  'description': '每日自动聚合免费节点，输出固定订阅链接',
  'private': False,
  'has_issues': False,
  'has_wiki': False,
  'auto_init': False,
}))" )" || true)

case "$CODE" in
  201) echo "      已创建" ;;
  422) echo "      仓库已存在，复用" ;;
  *)   head -c 300 /tmp/_repo.json; echo; die "创建失败 HTTP $CODE" ;;
esac

# ---------- 3. 配置 remote ----------
echo "[3/6] 配置 remote"
git remote remove origin 2>/dev/null || true
git remote add origin "https://${LOGIN}:${TOKEN}@github.com/${LOGIN}/${REPO_NAME}.git"
git branch -M main 2>/dev/null || true

# ---------- 4. 推送 ----------
echo "[4/6] 推送"
if git rev-parse HEAD >/dev/null 2>&1; then
  git push -u origin main --force 2>&1 | sed 's/^/      /'
else
  die "本地没有提交，请先在 gh-sub 目录 git init && git add -A && git commit"
fi

# ---------- 5. 校验可达性 ----------
echo "[5/6] 校验订阅地址"
RAW="https://raw.githubusercontent.com/${LOGIN}/${REPO_NAME}/main/output/sub.txt"
MIRROR="https://gh-proxy.com/https://raw.githubusercontent.com/${LOGIN}/${REPO_NAME}/main/output/sub.txt"
sleep 5
for u in "$MIRROR" "$RAW"; do
  c=$(curl -sS -m 25 -o /tmp/_sub.txt -w '%{http_code}' "$u" 2>/dev/null || echo 000)
  n=0
  if [ "$c" = "200" ]; then
    n=$(python3 - <<'PY' 2>/dev/null || echo 0
import base64
s=open('/tmp/_sub.txt').read().strip()
d=base64.b64decode(s+'='*(-len(s)%4)).decode('utf-8','ignore')
print(sum(1 for l in d.splitlines() if l.strip() and '://' in l))
PY
)
  fi
  printf "      [%s] %-3s 条  %s\n" "$c" "$n" "$u"
done

# ---------- 6. 触发 Actions 并给出结论 ----------
echo "[6/6] 触发一次 Actions"
curl -sS -m 30 -o /dev/null -w '      HTTP %{http_code}\n' \
  -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "$API/repos/${LOGIN}/${REPO_NAME}/actions/workflows/daily.yml/dispatches" \
  -d '{"ref":"main"}' || echo "      触发失败（可到网页手动 Run workflow）"

cat <<EOF

════════ 完成 ════════
仓库   https://github.com/${LOGIN}/${REPO_NAME}
Actions https://github.com/${LOGIN}/${REPO_NAME}/actions

订阅地址（三选一，按网络环境）:
  国内可直连  $MIRROR
  直连        $RAW
  mihomo 用   ${RAW%sub.txt}mihomo.yaml

加进本地 subs-check:
  docker exec subs-check-pro sh -c "grep -q '${LOGIN}/${REPO_NAME}' /app/config/config.yaml || sed -i '/^sub-urls:/a\\\\  - ${MIRROR}' /app/config/config.yaml"
  docker restart subs-check-pro
══════════════════════
EOF
