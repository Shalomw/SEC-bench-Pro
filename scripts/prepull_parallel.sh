#!/usr/bin/env bash
# Run one prepull_secbench.sh per task, in parallel, against a fast mirror.
# Usage: MIRROR=docker.1ms.run ./prepull_parallel.sh <task-file>
set -uo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
TASKS_FILE="${1:?usage: MIRROR=... prepull_parallel.sh <task-file>}"
export MIRROR="${MIRROR:-docker.1ms.run}"
LOGDIR="$BASE/logs/prepull"
mkdir -p "$LOGDIR"

pids=()
while read -r project id; do
  [ -z "${project:-}" ] && continue
  case "$project" in \#*) continue ;; v8|sm) ;; *) echo "skip $project"; continue ;; esac
  tf="$LOGDIR/task_${project}_${id}.txt"
  printf '%s %s\n' "$project" "$id" > "$tf"
  ./prepull_secbench.sh "$tf" > "$LOGDIR/${project}_${id}.launcher.log" 2>&1 &
  pids+=($!)
  echo "[$(date '+%F %T')] launched $project/$id pid=$!"
done < "$TASKS_FILE"

rc=0
for p in "${pids[@]}"; do wait "$p" || rc=1; done
echo "[$(date '+%F %T')] all prepulls done rc=$rc"
for f in "$LOGDIR"/*.launcher.log; do
  [ -f "$f" ] || continue
  echo "--- $(basename "$f")"; grep -E "OK |FAIL |PULL " "$f" | tail -2
done
