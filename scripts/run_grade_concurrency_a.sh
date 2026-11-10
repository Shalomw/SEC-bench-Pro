#!/usr/bin/env bash
# Grade SEC-bench-Pro concurrency A outputs with the official harness.
# Usage: ./run_grade_concurrency_a.sh [out-suffix] [workers]
#   out-suffix: "" for wave 1 ("concurrency_a"), "_w2" for wave 2.
set -euo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
export PATH="$HOME/.local/bin:$PATH"

set -a
# shellcheck source=/dev/null
source "$HOME/Projects/egrun/.secrets/env"
set +a
# litellm: deepseek/ provider uses DEEPSEEK_API_KEY; OPENAI_API_KEY silences
# the harness's non-Anthropic key check.
export DEEPSEEK_API_KEY="$ARTEX_LLM_API_KEY"
export OPENAI_API_KEY="$ARTEX_LLM_API_KEY"
export SECB_MAX_JS_CONTAINERS="${SECB_MAX_JS_CONTAINERS:-6}"

SUFFIX="${1:-}"
WORKERS="${2:-5}"
LOGDIR="$BASE/logs/concurrency_a${SUFFIX}"
mkdir -p "$LOGDIR"

run_grade() {
  local project="$1" outdir="$2" bench="$3" workers="$4"
  echo "[$(date '+%F %T')] grade $project workers=$workers dir=$outdir"
  local rc=0
  "$BASE/.venv/bin/python" "$BASE/harness/grade.py" \
    --project "$project" \
    --target-dir "$outdir" \
    --benchmark-dir "$bench" \
    --pull-missing \
    --judge-model "deepseek/deepseek-chat" \
    --js-grading-time-budget 10800 \
    --workers "$workers" \
    --judge-workers "$workers" \
    > "$LOGDIR/grade_${project}.log" 2>&1 || rc=$?
  echo "[$(date '+%F %T')] grade $project done rc=$rc (log: $LOGDIR/grade_${project}.log)"
}

run_grade v8 "$BASE/harness/output/v8/artex/concurrency_a${SUFFIX}" "$BASE/projects/v8" "$WORKERS"
run_grade sm "$BASE/harness/output/sm/artex/concurrency_a${SUFFIX}" "$BASE/projects/sm" 1
