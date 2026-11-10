#!/usr/bin/env bash
# CodeScan-Artex on SEC-bench-Pro concurrency A wave 1:
# 5 v8 instances in parallel + 1 sm instance, whole-source, findings-only.
set -uo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
set -a
# shellcheck source=/dev/null
source "$HOME/Projects/egrun/.secrets/env"
set +a

mkdir -p logs/codescan_shards harness/output/v8/codescan/concurrency_a harness/output/sm/codescan/concurrency_a

for id in 385775375 443182220 447307165 390201806 394635429; do
  sed "s/^instances = .*/instances = [\"$id\"]/" \
    harness/configs/codescan/v8/config.concurrency.toml > "/tmp/cs_v8_$id.toml"
done

# sm in parallel with the v8 shards
PYTHONUNBUFFERED=1 .venv/bin/python harness/eval_codescan.py --no-tui \
  harness/configs/codescan/sm/config.concurrency.toml \
  > logs/codescan_sm_batch.log 2>&1 &
sm_pid=$!

printf '%s\n' /tmp/cs_v8_*.toml | xargs -P 5 -I{} bash -c \
  'PYTHONUNBUFFERED=1 .venv/bin/python harness/eval_codescan.py --no-tui "{}" > "logs/codescan_shards/$(basename {} .toml).log" 2>&1'

wait "$sm_pid" || true
echo "[$(date '+%F %T')] codescan batch finished"
