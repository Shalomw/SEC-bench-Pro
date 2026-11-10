#!/usr/bin/env bash
# Wait for prepull_parallel.sh to finish, verify images, then start agents.
# Usage: ./chain_prepull_run.sh <task-file>
set -uo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
TASKS="${1:-tasks_concurrency_a_wave1.txt}"

while pgrep -f "prepull_parallel[.]sh" >/dev/null 2>&1; do
  sleep 30
done
echo "[$(date '+%F %T')] prepull launcher exited"

missing=0
while read -r project id; do
  [ -z "${project:-}" ] && continue
  case "$project" in \#*) continue ;; v8|sm) ;; *) continue ;; esac
  img=$("$BASE/.venv/bin/python" -c "import json;print(json.load(open('projects/$project/$id/meta.json'))['image_name'])" 2>/dev/null)
  if docker image inspect "$img" >/dev/null 2>&1; then
    echo "[$(date '+%F %T')] OK $img"
  else
    echo "[$(date '+%F %T')] MISSING $img"
    missing=1
  fi
done < "$TASKS"

if [ "$missing" -ne 0 ]; then
  echo "[$(date '+%F %T')] abort: missing images"
  exit 1
fi

setsid nohup ./run_secbench_concurrency_a.sh "$TASKS" 6 > logs/concurrency_a_wave1_run.log 2>&1 < /dev/null &
echo "[$(date '+%F %T')] agents launched"
