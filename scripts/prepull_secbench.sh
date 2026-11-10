#!/usr/bin/env bash
# Serial image pre-puller for SEC-bench-Pro.
# One docker pull at a time (full bandwidth); retries transient mirror resets.
# Usage: ./prepull_secbench.sh <task-file>   (lines: "<project> <instance_id>")
set -uo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
TASKS_FILE="${1:?usage: prepull_secbench.sh <task-file>}"
LOGDIR="$BASE/logs/prepull"
mkdir -p "$LOGDIR"
PY="$BASE/.venv/bin/python"

while read -r project id; do
  [ -z "${project:-}" ] && continue
  case "$project" in v8|sm) ;; *) echo "skip $project"; continue ;; esac
  img=$("$PY" -c "import json;print(json.load(open('projects/$project/$id/meta.json'))['image_name'])" 2>/dev/null) \
    || { echo "[$(date '+%F %T')] no meta for $project/$id"; continue; }
  src="$img"
  if [ -n "${MIRROR:-}" ]; then src="${MIRROR%/}/$img"; fi
  log="$LOGDIR/${project}_${id}.log"
  echo "[$(date '+%F %T')] PULL $project/$id $src"
  ok=0
  for attempt in $(seq 1 10); do
    if docker image inspect "$img" >/dev/null 2>&1; then ok=1; break; fi
    timeout 10800 docker pull "$src" > "$log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ] && [ "$src" != "$img" ] && docker image inspect "$src" >/dev/null 2>&1; then
      docker tag "$src" "$img" || true
      docker rmi "$src" >/dev/null 2>&1 || true
    fi
    if [ "$rc" -eq 0 ] && docker image inspect "$img" >/dev/null 2>&1; then
      ok=1
      break
    fi
    echo "[$(date '+%F %T')] attempt $attempt failed rc=$rc: $(tail -1 "$log" 2>/dev/null | tr -d '\r' | cut -c1-200)"
    sleep 30
  done
  if [ "$ok" -eq 1 ]; then
    echo "[$(date '+%F %T')] OK $img"
  else
    echo "[$(date '+%F %T')] FAIL $img"
  fi
done < "$TASKS_FILE"
echo "[$(date '+%F %T')] prepull finished"
