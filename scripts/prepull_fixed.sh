#!/usr/bin/env bash
# Pre-pull SEC-bench fixed images through the fast mirror.
# Usage: ./prepull_fixed.sh <id> [id...]   (project v8 only for now)
set -uo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
LOGDIR="$BASE/logs/prepull"
mkdir -p "$LOGDIR"

for spec in "$@"; do
  project="${spec%%:*}"
  id="${spec##*:}"
  case "$project" in
    v8) repo="hwiwonlee/v8.x86_64.fixed" ;;
    sm) repo="hwiwonlee/sm.x86_64.fixed" ;;
    *) echo "skip $spec"; continue ;;
  esac
  src="docker.1ms.run/$repo:$id"
  dst="$repo:$id"
  (
    ok=0
    for attempt in $(seq 1 8); do
      if docker image inspect "$dst" >/dev/null 2>&1; then ok=1; break; fi
      timeout 10800 docker pull "$src" && {
        docker tag "$src" "$dst" || true
        docker rmi "$src" >/dev/null 2>&1 || true
        ok=1
        break
      }
      echo "[$(date '+%F %T')] retry $id attempt=$attempt"
      sleep 30
    done
    if [ "$ok" -eq 1 ]; then echo "[$(date '+%F %T')] OK $dst"; else echo "[$(date '+%F %T')] FAIL $dst"; fi
  ) > "$LOGDIR/fixed_${project}_${id}.log" 2>&1 &
done
wait
echo "[$(date '+%F %T')] fixed prepull done"
