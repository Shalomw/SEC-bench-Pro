#!/usr/bin/env bash
# ARTEX x SEC-bench-Pro: concurrency A group.
# Each instance gets its own TOML so several eval_artex.py processes can run in
# parallel (the official eval loop is sequential per process).
#
# Usage: ./run_secbench_concurrency_a.sh <task-file> [parallel]
# Task file lines: "<project> <instance_id>"  (v8|sm), '#' comments allowed.
set -euo pipefail

BASE="$HOME/Projects/secbench-artex"
cd "$BASE"
export PATH="$HOME/.local/bin:$PATH"

# Same DeepSeek endpoint as the ExploitGym runs.
set -a
# shellcheck source=/dev/null
source "$HOME/Projects/egrun/.secrets/env"
set +a
if [ -z "${ARTEX_ZIP_PATH:-}" ]; then
  if [ -f "$BASE/artex-fork-linux-amd64.zip" ]; then
    ARTEX_ZIP_PATH="$BASE/artex-fork-linux-amd64.zip"
  else
    ARTEX_ZIP_PATH=/tmp/artex-fork-linux-amd64.zip
  fi
fi
export ARTEX_ZIP_PATH

TASKS_FILE="${1:?usage: run_secbench_concurrency_a.sh <task-file> [parallel]}"
PARALLEL="${2:-6}"
OUT_SUFFIX="${SECBENCH_OUT_SUFFIX:-}"
LOGDIR="$BASE/logs/concurrency_a${OUT_SUFFIX}"
CFGDIR="$(mktemp -d /tmp/secbench-cfg.XXXXXX)"
mkdir -p "$LOGDIR" "$BASE/harness/output/v8/artex/concurrency_a${OUT_SUFFIX}" "$BASE/harness/output/sm/artex/concurrency_a${OUT_SUFFIX}"

write_cfg() {
  local id="$1" project="$2" outdir prompt images cfg
  case "$project" in
    v8) outdir="output/v8/artex/concurrency_a${OUT_SUFFIX}"
        prompt="../prompts/baseline/task_prompt_v8.j2"
        images="../projects/v8" ;;
    sm) outdir="output/sm/artex/concurrency_a${OUT_SUFFIX}"
        prompt="../prompts/baseline/task_prompt_sm.j2"
        images="../projects/sm" ;;
    *) echo "unsupported project: $project" >&2; return 2 ;;
  esac
  cfg="$CFGDIR/${project}_${id}.toml"
  cat > "$cfg" <<EOF
model = "${ARTEX_LLM_MODEL:-deepseek-flash[1m]}"
provider = "anthropic"
outdir = "$outdir"
project = "$project"
instances = ["$id"]
timeout = ${SECBENCH_TIMEOUT:-5400}
prompt_template = "$prompt"
images_dir = "$images"
artex_zip = "$ARTEX_ZIP_PATH"
worker_count = ${SECBENCH_WORKERS:-2}
privileged = false
seed_first_intent = ${SECBENCH_SEED_FIRST_INTENT:-true}
EOF
  printf '%s\n' "$cfg"
}

run_one() {
  local project="$1" id="$2" cfg rc
  if [ ! -f "$ARTEX_ZIP_PATH" ]; then
    echo "missing ARTEX zip: $ARTEX_ZIP_PATH" >&2
    return 1
  fi
  cfg="$(write_cfg "$id" "$project")" || return 1
  echo "[$(date '+%F %T')] START $project/$id"
  set +e
  "$BASE/.venv/bin/python" "$BASE/harness/eval_artex.py" --no-tui "$cfg" \
    > "$LOGDIR/${project}_${id}.log" 2>&1
  rc=$?
  set -e
  echo "[$(date '+%F %T')] END   $project/$id rc=$rc (log: $LOGDIR/${project}_${id}.log)"
  return "$rc"
}
export -f write_cfg run_one
export BASE LOGDIR CFGDIR OUT_SUFFIX ARTEX_ZIP_PATH ARTEX_LLM_MODEL ARTEX_LLM_API_KEY ARTEX_LLM_BASE_URL

echo "[$(date '+%F %T')] task file: $TASKS_FILE  parallel=$PARALLEL"
grep -vE '^[[:space:]]*(#|$)' "$TASKS_FILE" | awk '{print $1, $2}' | \
  xargs -P "$PARALLEL" -n 2 bash -c 'run_one "$0" "$1"' || true

echo "[$(date '+%F %T')] batch finished"
grep -h "Results:" "$LOGDIR"/*.log 2>/dev/null | tail -20 || true
