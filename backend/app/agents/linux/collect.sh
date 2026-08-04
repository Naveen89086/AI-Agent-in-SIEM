#!/usr/bin/env bash
# -----------------------------------------------------------------------------
#  SIEM Endpoint Agent (Linux)
#  Tails security-relevant logs and ships them to the SIEM HTTP collector.
#  Works out of the box on systemd distros. Run as root for full log access.
#  Usage:  ./collect.sh http://localhost:8000/api/v1/ingest/events 60
# -----------------------------------------------------------------------------
set -u

COLLECTOR_URL="${1:-http://localhost:8000/api/v1/ingest/events}"
INTERVAL="${2:-60}"
SOURCE_NAME="${HOSTNAME:-linux-endpoint}"
SYSLOG_DIR="${SYSLOG_DIR:-/var/log}"
STATE_FILE="${STATE_FILE:-/tmp/siem_agent_state}"
BATCH_SIZE="${BATCH_SIZE:-200}"

FILES=(
  "$SYSLOG_DIR/auth.log"
  "$SYSLOG_DIR/secure"
  "$SYSLOG_DIR/syslog"
  "$SYSLOG_DIR/kern.log"
  "$SYSLOG_DIR/ufw.log"
  "$SYSLOG_DIR/messages"
  "$SYSLOG_DIR/dpkg.log"
)

declare -A OFFSETS
if [[ -f "$STATE_FILE" ]]; then
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    OFFSETS["$line"]=1
  done < "$STATE_FILE"
fi

send_batch() {
  local json
  json=$(printf '%s' "$1")
  if [[ -z "$json" ]]; then return; fi
  curl -sS -X POST "$COLLECTOR_URL" \
    -H "Content-Type: application/json" \
    -d "{\"events\":[$json]}" --max-time 10 || echo "WARN: ship failed" >&2
}

main() {
  local batch=""
  local count=0
  for file in "${FILES[@]}"; do
    [[ -f "$file" ]] || continue
    local size line
    size=$(stat -c %s "$file" 2>/dev/null || echo 0)
    [[ -z "${OFFSETS[$file]:-}" ]] && OFFSETS[$file]=0
    if (( size < OFFSETS[$file] )); then OFFSETS[$file]=0; fi

    tail -c "+$(( OFFSETS[$file] + 1 ))" "$file" | while IFS= read -r line; do
      local ts host
      ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
      host="$HOSTNAME"
      local rec
      rec=$(printf '{"message":%s,"source_type":"linux","source_name":"%s","host":"%s","timestamp":"%s","extra":{"file":"%s"},"tags":["linux","%s"]}' \
        "$(printf '%s' "$line" | python3 -c 'import sys,json;print(json.dumps(sys.stdin.read()[:4000]))' 2>/dev/null || printf '""')" \
        "$SOURCE_NAME" "$host" "$ts" "$file" "${file##*/}")
      if [[ -n "$batch" ]]; then batch="$batch,"; fi
      batch="$batch$rec"
      count=$((count + 1))
      if (( count >= BATCH_SIZE )); then
        send_batch "$batch"
        batch=""
        count=0
      fi
    done
    OFFSETS[$file]=$(stat -c %s "$file" 2>/dev/null || echo 0)
  done
  if [[ -n "$batch" ]]; then send_batch "$batch"; fi

  : > "$STATE_FILE"
  for k in "${!OFFSETS[@]}"; do echo "$k:${OFFSETS[$k]}" >> "$STATE_FILE"; done
}

while true; do
  main
  sleep "$INTERVAL"
done
