#!/usr/bin/env bash
# canvas-mcp self-hosted (Entra, multi-user): interactively generate the .env file.
#
# Run it in the deployment directory (for example /opt/canvas-mcp):
#   curl -fsSLO https://raw.githubusercontent.com/KKazuhaK/canvas-mcp/uci-student/deploy/selfhost/setup-env.sh
#   bash setup-env.sh
# Download it to a file first and run it with bash; do not use curl ... | bash (standard
# input is reserved for the client secret).
#
# What it does:
#   - Generates three random secrets with the local openssl: OAUTH_JWT_SIGNING_KEY,
#     ACCOUNT_SESSION_SECRET and CANVAS_TOKEN_KEYS. They are written to .env only and
#     are never printed;
#   - Asks for the public address, the Entra tenant ID and client ID, and the Canvas
#     address. They can also be supplied up front through environment variables of the
#     same names (PUBLIC_BASE_URL, ENTRA_TENANT_ID, ENTRA_CLIENT_ID, CANVAS_API_URL);
#     anything already supplied is not asked again;
#   - Reads the Entra client secret from standard input without echoing it to the
#     terminal. It deliberately accepts neither a command-line argument nor an
#     environment variable, so the secret never reaches the shell history or the
#     process list;
#   - Writes .env with mode 600: it writes a temporary file first and moves it into
#     place only when complete, so the file is either complete or absent. It refuses to
#     overwrite an existing file.
#
# Run it only once. To change settings later, edit .env and run docker compose up -d.
# Regenerating replaces CANVAS_TOKEN_KEYS: the enrolled Canvas tokens could no longer be
# decrypted and the service would refuse to start.
#
# Every value is validated first; if any of them is invalid the script exits with an
# error and never writes a half-finished file.
[ -n "${BASH_VERSION:-}" ] || { echo "Please run it with bash: bash setup-env.sh" >&2; exit 1; }
set -euo pipefail
# Do not trace execution: bash -x would print the client secret and the generated secrets to the terminal.
{ set +x; } 2>/dev/null

usage() {
  cat <<'EOF'
Usage: bash setup-env.sh [--enable-writes] [--real-names] [--school-search] [--output FILE]

Generate the .env for self-hosted multi-user mode in the deployment directory
(for example /opt/canvas-mcp).

  --enable-writes  Allow all 11 student write tools on the server and allow writes in
                   courses that have no instructor policy. This is only the server
                   ceiling: every write tool stays off for each user until that user turns
                   it on in the "Write tools" section of /account. Read-only by default;
                   for the risks see README.md ("Prompt-injection risk of write tools").
  --real-names     Turn data anonymization off (ENABLE_DATA_ANONYMIZATION=false; the
                   image default is on).
  --school-search  Let each user pick their own school: writes CANVAS_SCHOOL_SEARCH=true and
                   CANVAS_FEATURED_SCHOOLS=<host of CANVAS_API_URL>. Search terms are sent to
                   Instructure's public school directory; see README.md (multiple schools).
  --output FILE    Output file, default ./.env
  -h, --help       Show this help

Non-secret values can be supplied up front through environment variables:
PUBLIC_BASE_URL, ENTRA_TENANT_ID, ENTRA_CLIENT_ID, CANVAS_API_URL. The client secret is
read from the terminal only (not echoed).

Run it only once: to change settings later, edit .env and run docker compose up -d.
Regenerating replaces CANVAS_TOKEN_KEYS, and the enrolled Canvas tokens could no longer be decrypted.
EOF
}

die() {
  echo "Error: $*" >&2
  exit 1
}

OUTPUT=".env"
ENABLE_WRITES=false
REAL_NAMES=false
SCHOOL_SEARCH=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --enable-writes) ENABLE_WRITES=true ;;
    --real-names) REAL_NAMES=true ;;
    --school-search) SCHOOL_SEARCH=true ;;
    --output)
      [ "$#" -ge 2 ] || die "--output needs a file name"
      OUTPUT="$2"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "Unknown argument: $1 (use --help for usage)" ;;
  esac
  shift
done

command -v openssl >/dev/null 2>&1 || die "openssl is required (Debian/Ubuntu: apt install -y openssl)"

# Confirm we can write before asking anything, so a failure does not come after the secret has been pasted.
[ -n "$OUTPUT" ] || die "--output must not be empty"
OUT_DIR="$(dirname -- "$OUTPUT")"
[ -d "$OUT_DIR" ] && [ -w "$OUT_DIR" ] || die "Directory $OUT_DIR does not exist or is not writable"
if [ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]; then
  die "$OUTPUT already exists and will not be overwritten. To change settings, just edit $OUTPUT and run docker compose up -d.
Regenerating replaces secrets such as CANVAS_TOKEN_KEYS: the Canvas tokens already enrolled in /data could no longer be decrypted and the service would refuse to start.
If you really want to start over, back $OUTPUT up elsewhere and delete it, then copy the old CANVAS_TOKEN_KEYS into the new file (or clear the token database and have everyone enroll again)."
fi

# ask VAR PROMPT: if the variable already has a value (from the environment) use it, otherwise read one line from standard input.
ask() {
  local name="$1" prompt="$2" value="${!1:-}"
  if [ -z "$value" ]; then
    read -r -p "$prompt: " value || true
  fi
  # Text copied from Windows may carry a trailing \r.
  value="${value%$'\r'}"
  printf -v "$name" '%s' "$value"
}

# check_port NAME URL: if the URL contains a port, it must be between 1 and 65535.
check_port() {
  if [[ "$2" =~ ^https://[^/:]+:([0-9]+)(/|$) ]]; then
    local port=$((10#${BASH_REMATCH[1]}))
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "The port in $1 must be between 1 and 65535"
  fi
}

GUID_RE='^[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}$'
HOST_RE='[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?'
# https, a host name and an optional port; no path, query string or trailing slash.
BASE_URL_RE="^https://${HOST_RE}\$"
# https, a host name and an optional port, followed only by / or /api/v<N> (the server uses only that part; any other path is dropped).
CANVAS_URL_RE="^https://${HOST_RE}(/|/api/v[0-9]+/?)?\$"

ask PUBLIC_BASE_URL "Public address of the service (for example https://canvas.example.com, no trailing slash)"
[[ "$PUBLIC_BASE_URL" =~ $BASE_URL_RE ]] \
  || die "PUBLIC_BASE_URL must be https://host-name with no path, query string or trailing slash"
check_port PUBLIC_BASE_URL "$PUBLIC_BASE_URL"

ask ENTRA_TENANT_ID "Entra directory (tenant) ID"
[[ "$ENTRA_TENANT_ID" =~ $GUID_RE ]] \
  || die "ENTRA_TENANT_ID must be a GUID (common / organizations / consumers are not allowed)"

ask ENTRA_CLIENT_ID "Entra application (client) ID"
[[ "$ENTRA_CLIENT_ID" =~ $GUID_RE ]] || die "ENTRA_CLIENT_ID must be a GUID"
[ "${ENTRA_TENANT_ID,,}" != "${ENTRA_CLIENT_ID,,}" ] \
  || die "ENTRA_CLIENT_ID and ENTRA_TENANT_ID are the same: copy the two different IDs from the app's Overview page"

ask CANVAS_API_URL "Canvas address (for example https://canvas.school.edu)"
[[ "$CANVAS_API_URL" =~ $CANVAS_URL_RE ]] \
  || die "CANVAS_API_URL must be https://canvas-host-name (optionally with /api/v1); do not paste a full address such as a course page"
check_port CANVAS_API_URL "$CANVAS_API_URL"
CANVAS_API_URL="${CANVAS_API_URL%/}"
# Host of the default school: no scheme, port or path, lowercase (a CANVAS_FEATURED_SCHOOLS entry).
CANVAS_HOST=""
[[ "$CANVAS_API_URL" =~ ^https://([^/:]+) ]] && CANVAS_HOST="${BASH_REMATCH[1],,}"
[ -n "$CANVAS_HOST" ] || die "Could not read the host name from CANVAS_API_URL"

ENTRA_CLIENT_SECRET=""
if [ -t 0 ]; then
  read -r -s -p "Paste the Entra client secret Value (the Value column, not the Secret ID; input is not shown): " ENTRA_CLIENT_SECRET || true
  echo >&2
else
  read -r ENTRA_CLIENT_SECRET || true
fi
ENTRA_CLIENT_SECRET="${ENTRA_CLIENT_SECRET%$'\r'}"
[ -n "$ENTRA_CLIENT_SECRET" ] \
  || die "No client secret was read. Download the script to a file and run it: bash setup-env.sh (do not use curl ... | bash)"
[[ ! "$ENTRA_CLIENT_SECRET" =~ $GUID_RE ]] \
  || die "This looks like the Secret ID (a GUID). You need the Value column next to it"
[ "${#ENTRA_CLIENT_SECRET}" -ge 16 ] \
  || die "The client secret is too short: you need the Value column (at least 16 characters)"
case "$ENTRA_CLIENT_SECRET" in
  *[[:space:]\"\'\$\\\`]*) die "The client secret contains whitespace, a quote, \$, a backslash or a backtick, which is not what Entra generates; copy the Value again" ;;
esac

OAUTH_JWT_SIGNING_KEY="$(openssl rand -base64 48 | tr -d '\r\n')"
ACCOUNT_SESSION_SECRET="$(openssl rand -base64 32 | tr -d '\r\n')"
CANVAS_TOKEN_KEY="$(openssl rand -base64 32 | tr -d '\r\n')"
[ "${#OAUTH_JWT_SIGNING_KEY}" -eq 64 ] && [ "${#ACCOUNT_SESSION_SECRET}" -eq 44 ] \
  && [ "${#CANVAS_TOKEN_KEY}" -eq 44 ] || die "openssl generated a key of the wrong length"

STUDENT_WRITE_TOOLS_ALL="submit_assignment,comment_on_my_submission,mark_module_item_done,create_planner_note,update_planner_note,delete_planner_note,mark_planner_item_complete,create_personal_calendar_event,delete_personal_calendar_event,send_message,reply_to_conversation"

render() {
  cat <<EOF
# canvas-mcp self-hosted configuration, generated by setup-env.sh. It contains secrets: keep
# it chmod 600, never commit it to git, never paste it into a chat; keep an offline copy
# (losing CANVAS_TOKEN_KEYS = everyone has to enroll their Canvas token again).
# To change settings later, edit this file and run docker compose up -d (restart does not re-read .env).
# Do not rerun setup-env.sh: it would replace the secrets below and the enrolled Canvas tokens could no longer be decrypted.
# See env.example and README.md for what each setting means.

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

# Write tools: allowed on the server (--enable-writes). This is only the ceiling: every write
# tool stays off for each user until that user turns it on in the "Write tools" section of
# /account (README.md, "Write tools: each user opts in"). The discussions and announcements
# the AI reads may carry prompt injection; have every user set the write tools to Ask before
# using in claude.ai.
ALLOWED_WRITE_TOOLS=all
STUDENT_WRITE_TOOLS=${STUDENT_WRITE_TOOLS_ALL}
COURSE_AGENT_POLICY_DEFAULT=allow
EOF
  else
    cat <<EOF

# Write tools: off (read-only). To enable them: read the README.md section
# "Prompt-injection risk of write tools" first, remove the leading "# " from the three
# lines below, then run docker compose up -d.
# ALLOWED_WRITE_TOOLS=all
# STUDENT_WRITE_TOOLS=${STUDENT_WRITE_TOOLS_ALL}
# COURSE_AGENT_POLICY_DEFAULT=allow
EOF
  fi
  if [ "$SCHOOL_SEARCH" = true ]; then
    cat <<EOF

# Multiple schools: enabled (--school-search). Users pick a school on /account.
# CANVAS_FEATURED_SCHOOLS lists the quick picks (host names only, comma separated,
# optionally host=Display Name). CANVAS_SCHOOL_SEARCH=true also lets users search
# Instructure's public school directory; the search terms are sent to Instructure
# and enrollment then needs outbound HTTPS to canvas.instructure.com.
CANVAS_FEATURED_SCHOOLS=${CANVAS_HOST}
CANVAS_SCHOOL_SEARCH=true
EOF
  else
    cat <<EOF

# Multiple schools: off (every user is on CANVAS_API_URL). To let users pick their
# own school, remove the leading "# " from the two lines below, then docker compose up -d.
# CANVAS_FEATURED_SCHOOLS=${CANVAS_HOST}
# CANVAS_SCHOOL_SEARCH=true
EOF
  fi
  if [ "$REAL_NAMES" = true ]; then
    cat <<EOF

# Data anonymization: off (--real-names); tool results show real names.
ENABLE_DATA_ANONYMIZATION=false
EOF
  fi
}

# Write a temporary file in the same directory first and, once it is complete and its
# permissions are set, hard-link it into place: ln fails when the target already exists,
# so it neither overwrites nor leaves behind a half-written .env.
umask 077
TMP_FILE="$(mktemp "$OUT_DIR/.setup-env.XXXXXX")"
trap 'rm -f -- "$TMP_FILE"' EXIT
trap 'exit 130' INT TERM HUP
render >"$TMP_FILE"
chmod 600 "$TMP_FILE"
if ! ln -- "$TMP_FILE" "$OUTPUT" 2>/dev/null; then
  [ ! -e "$OUTPUT" ] && [ ! -L "$OUTPUT" ] || die "$OUTPUT already exists and will not be overwritten"
  # Fall back to a noclobber copy when the filesystem does not support hard links.
  (set -o noclobber && cat -- "$TMP_FILE" >"$OUTPUT") || die "Cannot write $OUTPUT"
  chmod 600 "$OUTPUT"
fi
rm -f -- "$TMP_FILE"
trap - EXIT
unset ENTRA_CLIENT_SECRET OAUTH_JWT_SIGNING_KEY ACCOUNT_SESSION_SECRET CANVAS_TOKEN_KEY

writes_label="off (read-only)"
[ "$ENABLE_WRITES" = true ] && writes_label="all enabled"
names_label="anonymized (image default)"
[ "$REAL_NAMES" = true ] && names_label="real names"
schools_label="Single school (CANVAS_API_URL)"
[ "$SCHOOL_SEARCH" = true ] && schools_label="Users pick a school; directory search on"

cat >&2 <<EOF

Wrote $OUTPUT (mode 600).
  Public address   $PUBLIC_BASE_URL
  Canvas           $CANVAS_API_URL (the server uses /api/v1)
  Write tools      $writes_label
  Name display     $names_label
  Schools          $schools_label

Next steps:
  1. Keep an offline copy of $OUTPUT (password manager).
  2. docker compose up -d && docker compose logs --tail 50
  3. curl -fsS http://127.0.0.1:8819/healthz   # should return ok
To change settings later: edit $OUTPUT and run docker compose up -d. Do not rerun this script.
EOF
