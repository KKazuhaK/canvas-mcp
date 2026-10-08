#!/usr/bin/env bash
# canvas-mcp 自托管（Entra 多用户）：交互式生成 .env。
#
# 在部署目录里运行（例如 /opt/canvas-mcp）：
#   curl -fsSLO https://raw.githubusercontent.com/KKazuhaK/canvas-mcp/uci-student/deploy/selfhost/setup-env.sh
#   bash setup-env.sh
# 要先下载成文件再用 bash 运行；不能用 curl ... | bash（标准输入要留给客户端密码）。
#
# 它会：
#   - 用本机 openssl 生成三个随机密钥：OAUTH_JWT_SIGNING_KEY、ACCOUNT_SESSION_SECRET、
#     CANVAS_TOKEN_KEYS。它们只写进 .env，不会打印出来；
#   - 询问公网地址、Entra 租户 ID 和客户端 ID、Canvas 地址。也可以用同名环境变量
#     预先给出（PUBLIC_BASE_URL、ENTRA_TENANT_ID、ENTRA_CLIENT_ID、CANVAS_API_URL），
#     给了就不再询问；
#   - 从标准输入读取 Entra 客户端密码，在终端里不回显。故意不接受命令行参数或环境变量，
#     免得密码进入 shell 历史或进程列表；
#   - 以 600 权限写出 .env：先写临时文件，写完整了再放到位，所以要么完整、要么不存在。
#     文件已存在时拒绝覆盖。
#
# 只运行一次。以后改设置直接编辑 .env，再 docker compose up -d。重新生成会换掉
# CANVAS_TOKEN_KEYS：已登记的 Canvas token 将无法解密，服务会拒绝启动。
#
# 每一项都会先校验，任何一项不合法都会报错退出，不会写出半成品文件。
[ -n "${BASH_VERSION:-}" ] || { echo "请用 bash 运行：bash setup-env.sh" >&2; exit 1; }
set -euo pipefail
# 不跟踪执行过程：bash -x 会把客户端密码和生成的密钥打印到终端。
{ set +x; } 2>/dev/null

usage() {
  cat <<'EOF'
用法：bash setup-env.sh [--enable-writes] [--real-names] [--output FILE]

在部署目录（例如 /opt/canvas-mcp）里生成自托管多用户模式的 .env。

  --enable-writes  开启全部 11 个学生写入工具，并允许在没有教师策略的课程里写入。
                   默认只读；风险见 README.md「写入工具的提示词注入风险」。
  --real-names     关闭数据匿名化（ENABLE_DATA_ANONYMIZATION=false，镜像默认开启）。
  --output FILE    输出文件，默认 ./.env
  -h, --help       显示这段说明

非机密的值可以用环境变量预先给出：PUBLIC_BASE_URL、ENTRA_TENANT_ID、
ENTRA_CLIENT_ID、CANVAS_API_URL。客户端密码只从终端读取（不回显）。

只运行一次：以后改设置直接编辑 .env 再 docker compose up -d。
重新生成会换掉 CANVAS_TOKEN_KEYS，已登记的 Canvas token 将无法解密。
EOF
}

die() {
  echo "错误：$*" >&2
  exit 1
}

OUTPUT=".env"
ENABLE_WRITES=false
REAL_NAMES=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --enable-writes) ENABLE_WRITES=true ;;
    --real-names) REAL_NAMES=true ;;
    --output)
      [ "$#" -ge 2 ] || die "--output 需要一个文件名"
      OUTPUT="$2"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "不认识的参数：$1（用 --help 查看用法）" ;;
  esac
  shift
done

command -v openssl >/dev/null 2>&1 || die "需要 openssl（Debian/Ubuntu：apt install -y openssl）"

# 在问任何问题之前先确认能写，免得粘贴完密码才失败。
[ -n "$OUTPUT" ] || die "--output 不能为空"
OUT_DIR="$(dirname -- "$OUTPUT")"
[ -d "$OUT_DIR" ] && [ -w "$OUT_DIR" ] || die "目录 $OUT_DIR 不存在或不可写"
if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
  die "$OUTPUT 已存在，不覆盖。只想改设置的话，直接编辑 $OUTPUT 再 docker compose up -d。
重新生成会换掉 CANVAS_TOKEN_KEYS 等密钥：/data 里已登记的 Canvas token 将无法解密，服务会拒绝启动。
确实要从头来，先把 $OUTPUT 备份到别处再删除，并把旧的 CANVAS_TOKEN_KEYS 抄回新文件（或者清空 token 数据库，让所有人重新登记）。"
fi

# ask VAR 提示：变量已经有值（来自环境变量）就直接用，否则从标准输入读一行。
ask() {
  local name="$1" prompt="$2" value="${!1:-}"
  if [ -z "$value" ]; then
    read -r -p "$prompt: " value || true
  fi
  # 从 Windows 复制粘贴时行尾可能带 \r。
  value="${value%$'\r'}"
  printf -v "$name" '%s' "$value"
}

# check_port 名称 URL：URL 里写了端口时，必须在 1-65535 之间。
check_port() {
  if [[ "$2" =~ ^https://[^/:]+:([0-9]+)(/|$) ]]; then
    local port=$((10#${BASH_REMATCH[1]}))
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "$1 的端口必须在 1-65535 之间"
  fi
}

GUID_RE='^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$'
HOST_RE='[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?'
# https、主机名、可选端口；不带路径、查询串、末尾斜杠。
BASE_URL_RE="^https://${HOST_RE}\$"
# https、主机名、可选端口，后面只能是 / 或 /api/v<N>（服务器只用这部分，别的路径会被丢掉）。
CANVAS_URL_RE="^https://${HOST_RE}(/|/api/v[0-9]+/?)?\$"

ask PUBLIC_BASE_URL "服务的公网地址（例如 https://canvas.example.com，不带末尾斜杠）"
[[ "$PUBLIC_BASE_URL" =~ $BASE_URL_RE ]] \
  || die "PUBLIC_BASE_URL 必须是 https://主机名，不带路径、查询串或末尾斜杠"
check_port PUBLIC_BASE_URL "$PUBLIC_BASE_URL"

ask ENTRA_TENANT_ID "Entra 目录(租户) ID"
[[ "$ENTRA_TENANT_ID" =~ $GUID_RE ]] \
  || die "ENTRA_TENANT_ID 必须是 GUID（不能写 common / organizations / consumers）"

ask ENTRA_CLIENT_ID "Entra 应用程序(客户端) ID"
[[ "$ENTRA_CLIENT_ID" =~ $GUID_RE ]] || die "ENTRA_CLIENT_ID 必须是 GUID"
[ "${ENTRA_TENANT_ID,,}" != "${ENTRA_CLIENT_ID,,}" ] \
  || die "ENTRA_CLIENT_ID 和 ENTRA_TENANT_ID 相同：请分别从应用「概述」页复制两个不同的 ID"

ask CANVAS_API_URL "Canvas 地址（例如 https://canvas.school.edu）"
[[ "$CANVAS_API_URL" =~ $CANVAS_URL_RE ]] \
  || die "CANVAS_API_URL 必须是 https://Canvas主机名（可以带 /api/v1），不要粘贴课程页面之类的完整地址"
check_port CANVAS_API_URL "$CANVAS_API_URL"
CANVAS_API_URL="${CANVAS_API_URL%/}"

ENTRA_CLIENT_SECRET=""
if [ -t 0 ]; then
  read -r -s -p "粘贴 Entra 客户端密码的「值」（Value 列，不是 Secret ID；输入不显示）: " ENTRA_CLIENT_SECRET || true
  echo >&2
else
  read -r ENTRA_CLIENT_SECRET || true
fi
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET%$'\r'}"
[ -n "$ENTRA_CLIENT_SECRET" ] \
  || die "没有读到客户端密码。请先把脚本下载成文件再运行：bash setup-env.sh（不能用 curl ... | bash）"
[[ ! "$ENTRA_CLIENT_SECRET" =~ $GUID_RE ]] \
  || die "这看起来是「密码 ID」(Secret ID，一个 GUID)。要的是旁边「值」(Value) 那一列"
[ "${#ENTRA_CLIENT_SECRET}" -ge 16 ] \
  || die "客户端密码太短：要的是「值」那一列（至少 16 个字符）"
case "$ENTRA_CLIENT_SECRET" in
  *[[:space:]\"\'\$\\\`]*) die "客户端密码含有空白、引号、\$、反斜杠或反引号，这不像 Entra 生成的密码，请重新复制「值」" ;;
esac

OAUTH_JWT_SIGNING_KEY="$(openssl rand -base64 48 | tr -d '\r\n')"
ACCOUNT_SESSION_SECRET="$(openssl rand -base64 32 | tr -d '\r\n')"
CANVAS_TOKEN_KEY="$(openssl rand -base64 32 | tr -d '\r\n')"
[ "${#OAUTH_JWT_SIGNING_KEY}" -eq 64 ] && [ "${#ACCOUNT_SESSION_SECRET}" -eq 44 ] \
  && [ "${#CANVAS_TOKEN_KEY}" -eq 44 ] || die "openssl 生成的密钥长度不对"

STUDENT_WRITE_TOOLS_ALL="submit_assignment,comment_on_my_submission,mark_module_item_done,create_planner_note,update_planner_note,delete_planner_note,mark_planner_item_complete,create_personal_calendar_event,delete_personal_calendar_event,send_message,reply_to_conversation"

render() {
  cat <<EOF
# canvas-mcp 自托管配置，由 setup-env.sh 生成。含密钥：保持 chmod 600，不要提交到 git、
# 不要贴到聊天里；离线备份一份（丢了 CANVAS_TOKEN_KEYS = 所有人重新登记 Canvas token）。
# 以后改设置直接编辑本文件，再 docker compose up -d（restart 不会重新读取 .env）。
# 不要重新运行 setup-env.sh：那会换掉下面的密钥，已登记的 Canvas token 将无法解密。
# 各项含义见 env.example 和 README.md。

MCP_AUTH_MODE=entra-oauth
PUBLIC_BASE_URL=${PUBLIC_BASE_URL}

ENTRA_TENANT_ID=${ENTRA_TENANT_ID}
ENTRA_CLIENT_ID=${ENTRA_CLIENT_ID}
ENTRA_CLIENT_SECRET=${ENTRA_CLIENT_SECRET}

OAUTH_JWT_SIGNING_KEY=${OAUTH_JWT_SIGNING_KEY}
ACCOUNT_SESSION_SECRET=${ACCOUNT_SESSION_SECRET}
CANVAS_TOKEN_KEYS=k1:${CANVAS_TOKEN_KEY}

CANVAS_API_URL=${CANVAS_API_URL}
CANVAS_ROLE=student
TIMEZONE=America/Los_Angeles
MCP_MAX_RESULT_CHARS=140000

FASTMCP_HOME=/data/fastmcp
EOF
  if [ "$ENABLE_WRITES" = true ]; then
    cat <<EOF

# 写入工具：已开启（--enable-writes）。AI 读到的讨论、公告里可能藏着提示词注入；
# 请让每个用户在 claude.ai 里把写入类工具设为 Ask before using。
ALLOWED_WRITE_TOOLS=all
STUDENT_WRITE_TOOLS=${STUDENT_WRITE_TOOLS_ALL}
COURSE_AGENT_POLICY_DEFAULT=allow
EOF
  else
    cat <<EOF

# 写入工具：关闭（只读）。要开启：先读 README.md「写入工具的提示词注入风险」，
# 删掉下面三行开头的 "# "，再 docker compose up -d。
# ALLOWED_WRITE_TOOLS=all
# STUDENT_WRITE_TOOLS=${STUDENT_WRITE_TOOLS_ALL}
# COURSE_AGENT_POLICY_DEFAULT=allow
EOF
  fi
  if [ "$REAL_NAMES" = true ]; then
    cat <<EOF

# 数据匿名化：已关闭（--real-names），工具结果里显示真实姓名。
ENABLE_DATA_ANONYMIZATION=false
EOF
  fi
}

# 先写同目录下的临时文件，完整写好、设好权限后再用硬链接放到位：
# ln 遇到已存在的目标会失败，所以既不会覆盖，也不会留下写了一半的 .env。
umask 077
TMP_FILE="$(mktemp "$OUT_DIR/.setup-env.XXXXXX")"
trap 'rm -f -- "$TMP_FILE"' EXIT
trap 'exit 130' INT TERM HUP
render >"$TMP_FILE"
chmod 600 "$TMP_FILE"
if ! ln -- "$TMP_FILE" "$OUTPUT" 2>/dev/null; then
  [ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || die "$OUTPUT 已存在，不覆盖"
  # 文件系统不支持硬链接时退回到 noclobber 复制。
  (set -o noclobber && cat -- "$TMP_FILE" >"$OUTPUT") || die "无法写入 $OUTPUT"
  chmod 600 "$OUTPUT"
fi
rm -f -- "$TMP_FILE"
trap - EXIT
unset ENTRA_CLIENT_SECRET OAUTH_JWT_SIGNING_KEY ACCOUNT_SESSION_SECRET CANVAS_TOKEN_KEY

writes_label="关闭（只读）"
[ "$ENABLE_WRITES" = true ] && writes_label="全部开启"
names_label="匿名化（镜像默认）"
[ "$REAL_NAMES" = true ] && names_label="真实姓名"

cat >&2 <<EOF

已写入 $OUTPUT（权限 600）。
  公网地址   $PUBLIC_BASE_URL
  Canvas     $CANVAS_API_URL（服务器会用 /api/v1）
  写入工具   $writes_label
  姓名显示   $names_label

下一步：
  1. 把 $OUTPUT 离线备份一份（密码管理器）。
  2. docker compose up -d && docker compose logs --tail 50
  3. curl -fsS http://127.0.0.1:8819/healthz   # 应返回 ok
以后改设置：直接编辑 $OUTPUT，再 docker compose up -d。不要重新运行本脚本。
EOF
