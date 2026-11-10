"""Run the CodeScan-Artex (SCA) engine as a SEC-bench Pro source-audit agent.

Usage::

    set -a; source ~/Projects/egrun/.secrets/env; set +a
    .venv/bin/python harness/eval_codescan.py --no-tui \
        harness/configs/codescan/v8/config.concurrency.toml

This mirrors the ExploitGym ``CodeScanAgent`` deployment shape: the SCA binary
and PostgreSQL are staged inside each benchmark container, the instance's
target source subtree is zipped and uploaded over the engine's HTTP API, and
the engine performs a static source audit. The deliverable is findings, not a
PoC. ``codescan_findings.json`` / ``codescan_meta.json`` are written under the
instance output directory; this script does not grade.

Required host environment:
    ARTEX_LLM_API_KEY   LLM key handed to the SCA engine
    ARTEX_LLM_BASE_URL  LLM base URL (default: https://api.deepseek.com/anthropic)
    ARTEX_LLM_MODEL     model name (default: deepseek-flash[1m])

Optional host environment:
    CODESCAN_BIN_PATH    host path of the built amd64 SCA binary
                         (config ``sca_bin`` overrides the default)
    CODESCAN_SKILLS_TGZ  optional skills tarball (config ``codescan_skills``)
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import shlex
import subprocess
import sys
import time
from pathlib import Path

import common
from common import (
    SCRIPT_DIR,
    docker_copy_from,
    docker_copy_to,
    docker_exec,
    docker_preflight,
    error,
    info,
    load_config,
    load_meta,
    resolve_instances,
    resolve_path,
    run_eval_loop,
    step_err,
    step_ok,
    step_run,
    step_warn,
    warn,
)

DEFAULT_BASE_URL = "https://api.deepseek.com/anthropic"
DEFAULT_MODEL = "deepseek-flash[1m]"
DEFAULT_PORT = 7878
POLL_INTERVAL = 20
TERMINAL_STATUSES = {"done", "failed", "timeout", "cancelled", "canceled"}
DEFAULT_SCA_BIN = Path.home() / "Projects/egrun/codescan/artex"
DEFAULT_SKILLS = Path.home() / "Projects/egrun/codescan/codescan-skills.tgz"
CODESCAN_HOME = "/opt/codescan"
ENGINE_LOG = "/tmp/codescan.log"
SOURCE_ZIP = "/tmp/src.zip"

INSTALL_BOOTSTRAP = r"""
set -euo pipefail
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  --no-install-recommends postgresql unzip zip curl >/dev/null
mkdir -p /opt/codescan/data /opt/codescan/skills
mv /tmp/codescan-sca /opt/codescan/sca
chmod +x /opt/codescan/sca
if [ -f /tmp/codescan-skills.tgz ]; then
  tar xzf /tmp/codescan-skills.tgz -C /opt/codescan/skills --strip-components=1 2>/dev/null || true
fi
cat > /opt/codescan/config.json <<'EOF'
{"database":{"host":"127.0.0.1","port":5432,"user":"artex","password":"artex","dbname":"artex","sslmode":"disable"}}
EOF
service postgresql start || pg_ctlcluster "$(ls /etc/postgresql | head -1)" main start
if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='artex'\"" | grep -q 1; then
  su postgres -c "psql -q -c \"CREATE ROLE artex LOGIN PASSWORD 'artex'\""
fi
su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='artex'\"" | grep -q 1 \
  || su postgres -c "createdb -O artex artex"
echo "codescan install bootstrap ok"
"""

RUN_BOOTSTRAP = r"""
cd /opt/codescan || { echo "no /opt/codescan"; exit 11; }
if [ -f /tmp/codescan.pid ] && kill -0 "$(cat /tmp/codescan.pid)" 2>/dev/null; then
  kill "$(cat /tmp/codescan.pid)" 2>/dev/null || true
  sleep 1
fi
export ANTHROPIC_API_KEY="$ARTEX_LLM_API_KEY"
export ARTEX_LLM_PROVIDER=anthropic
export ARTEX_LLM_BASE_URL="$ARTEX_LLM_BASE_URL"
export ARTEX_LLM_MODEL="$ARTEX_LLM_MODEL"
export ARTEX_LLM_PROXY="$ARTEX_LLM_PROXY"
export ARTEX_SKILL_DIR=/opt/codescan/skills
nohup ./sca -addr "127.0.0.1:${CODESCAN_PORT}" -data /opt/codescan/data >/tmp/codescan.log 2>&1 &
pid=$!
echo "$pid" > /tmp/codescan.pid
sleep 2
if ! kill -0 "$pid" 2>/dev/null; then
  echo "codescan died (pid=$pid); log:"
  cat /tmp/codescan.log 2>/dev/null
  exit 12
fi
echo "codescan started pid=$pid"
"""

OPERATIONS_BLOCK = """

## CodeScan-Artex 执行环境说明(重要)

- 本环境是**纯静态源码审计**:可用工具只有文件读取、搜索与编辑类工具,没有
  Shell、网络或二进制执行能力。
- 待审计源码已上传到任务目录的 `source/`(worker 工作目录下为 `../source/`),
  内部保留仓库相对路径。本次审计的源码范围:{source_entries}(相对源码根)。
- 源码内容与容器内 `{work_dir}/<相对路径>` 相同;若 `source/` 下找不到文件,
  可按相同相对路径在该目录查找。
- 引用源码时一律使用**仓库相对路径**(不要带 `source/` 或 `{work_dir}/` 前缀),
  例如 `{example_path}:行号`。
- 先覆盖目标源码文件,再沿调用关系扩展到审计范围内的必要文件;不要越出上述范围。
- 每条 finding 必须写明:`文件:行号`、关键代码片段、根因、以及数据流/时序分析;
  有源码证据但关键调用方不在范围内的候选缺陷也应登记,并注明缺口。
- 不要编写 PoC,不要运行任何二进制,不要生成 `audit/` 产物、stderr 或复现脚本。
"""


def _container_curl(
    container_id: str,
    method: str,
    path: str,
    body: dict | None = None,
    token: str | None = None,
    *,
    port: int = DEFAULT_PORT,
    timeout: int = 60,
) -> tuple[int, str]:
    """One HTTP call to the in-container SCA engine, via exec + curl."""
    cmd = [
        "curl", "-sS", "-m", str(timeout), "-w", "\n%{http_code}", "-X", method,
        f"http://127.0.0.1:{port}{path}", "-H", "Content-Type: application/json",
    ]
    if token:
        cmd += ["-H", f"Authorization: Bearer {token}"]
    if body is not None:
        cmd += ["-d", json.dumps(body)]
    rc, out, err = docker_exec(container_id, " ".join(shlex.quote(c) for c in cmd),
                               timeout_secs=timeout + 30)
    raw = (out or "") + (err or "")
    if rc != 0:
        return 0, raw
    body_text, _, status = raw.rpartition("\n")
    try:
        return int(status.strip()), body_text
    except ValueError:
        return 0, raw


def _json_or_none(text: str) -> dict | None:
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else None
    except (ValueError, TypeError):
        return None


def _findings_count(text: str) -> int:
    try:
        value = json.loads(text)
    except (ValueError, TypeError):
        return 0
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in ("items", "findings", "data"):
            items = value.get(key)
            if isinstance(items, list):
                return len(items)
    return 0


def _run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _cleanup(container_name: str) -> None:
    common.remove_registered_container(container_name, info_fn=info, warn_fn=warn)


def _select_source_entries(
    meta: dict, work_dir: str, configured: object = None
) -> list[str]:
    """Pick repo-relative archive roots.

    Config ``source_entries`` overrides meta.json; otherwise target_subdir is
    preferred over target_source_files.
    """
    raw_sources = (
        [configured]
        if configured
        else [meta.get("target_subdir") or [], meta.get("target_source_files") or []]
    )
    for raw in raw_sources:
        if isinstance(raw, str):
            raw = [raw]
        entries: list[str] = []
        for item in raw:
            path = str(item).strip()
            if not path:
                continue
            while path.startswith("./"):
                path = path[2:]
            path = path.lstrip("/")
            if path and path not in entries:
                entries.append(path)
        if entries:
            return entries
    return []


def _build_zip_cmd(work_dir: str, source_entries: list[str]) -> str:
    entry_args = " ".join(shlex.quote(entry) for entry in source_entries)
    return (
        "set -e\n"
        f"cd {shlex.quote(work_dir)}\n"
        "entries=()\n"
        f"for p in {entry_args}; do\n"
        '  if [ -e "$p" ]; then entries+=("$p"); fi\n'
        "done\n"
        'if [ ${#entries[@]} -eq 0 ]; then\n'
        '  echo "NO_SOURCE" >&2\n'
        f"  ls -la {shlex.quote(work_dir)} >&2 || true\n"
        "  exit 21\n"
        "fi\n"
        f"rm -f {SOURCE_ZIP}\n"
        f'zip -qr {SOURCE_ZIP} "${{entries[@]}}" '
        "-x '.git/*' -x '*/node_modules/*' -x '*/__pycache__/*'\n"
        'echo "SRC=${entries[*]}"\n'
        f"ls -l {SOURCE_ZIP} | awk '{{print \"ZIPBYTES=\" $5}}'\n"
    )


def run_instance(
    *,
    instance_id: str,
    image_name: str,
    work_dir: str,
    instance_outdir: Path,
    prompt: str,
    config: dict,
    instance_meta_dir: Path | None = None,
    **_kwargs: object,
) -> int:
    """Start one SEC-bench container, run SCA static audit, collect findings."""
    timeout_secs: int = int(config.get("timeout", 5400))
    worker_count = int(config.get("worker_count", 2))
    port = int(config.get("port", DEFAULT_PORT))
    base_url = os.environ.get("ARTEX_LLM_BASE_URL", DEFAULT_BASE_URL)
    model = os.environ.get("ARTEX_LLM_MODEL", config.get("model", DEFAULT_MODEL))
    proxy_url = os.environ.get(
        "ARTEX_LLM_PROXY", str(config.get("llm_proxy", "") or ""))
    api_key = os.environ.get("ARTEX_LLM_API_KEY")
    if not api_key:
        error("ARTEX_LLM_API_KEY is not set")
        return 1

    sca_bin = Path(
        os.environ.get("CODESCAN_BIN_PATH")
        or config.get("sca_bin")
        or str(DEFAULT_SCA_BIN)
    ).expanduser()
    skills_tgz = Path(
        os.environ.get("CODESCAN_SKILLS_TGZ")
        or config.get("codescan_skills")
        or str(DEFAULT_SKILLS)
    ).expanduser()
    if not sca_bin.is_file():
        error(f"SCA binary not found: {sca_bin}")
        return 1

    meta: dict = {}
    if instance_meta_dir is not None:
        meta_path = Path(instance_meta_dir) / instance_id / "meta.json"
        if meta_path.is_file():
            meta = load_meta(meta_path)
    source_entries = _select_source_entries(
        meta, work_dir, config.get("source_entries"))
    if not source_entries:
        error(f"no source_entries/target_subdir/target_source_files for {instance_id}")
        return 1
    target_files = meta.get("target_source_files") or []
    if isinstance(target_files, str):
        target_files = [target_files]
    example_path = source_entries[0]
    for item in target_files:
        candidate = str(item).strip()
        if candidate:
            example_path = candidate
            break

    container_name = (
        f"{config.get('container_prefix', 'codescan-eval')}"
        f"-{instance_id}-{int(time.time())}"
    )
    info(f"Image: {image_name}")
    info(f"Work dir: {work_dir}")
    info(f"Source entries: {', '.join(source_entries)}")

    if _run(["docker", "image", "inspect", image_name], timeout=60).returncode != 0:
        if config.get("pull_missing", False):
            info(f"Pulling Docker image: {image_name}")
            pulled = False
            for attempt in range(1, 7):
                pull = _run(["docker", "pull", image_name], timeout=43200)
                if pull.returncode == 0:
                    pulled = True
                    break
                warn(f"docker pull failed (attempt {attempt}/6): "
                     f"{pull.stderr.strip()[-300:]}")
                if attempt < 6:
                    time.sleep(60)
            if not pulled:
                error(f"docker pull failed: {image_name}")
                return 1
        else:
            error(
                f"Docker image not found locally: {image_name}; refusing to pull "
                "(set pull_missing = true to allow docker pull)"
            )
            return 1

    run_args = ["docker", "run", "--detach", "--name", container_name]
    if config.get("privileged", False) or common.is_linux_project(
            config.get("project", "")):
        run_args.append("--privileged")
    run_args += [image_name, "bash", "-c", "sleep infinity"]
    started = _run(run_args, timeout=120)
    if started.returncode != 0:
        error(f"docker run failed: {started.stderr[-600:]}")
        return 1
    container_id = started.stdout.strip()
    common.register_active_container(container_name)
    step_ok(f"Container started: {container_id[:12]}")

    try:
        step_run("Stage SCA binary")
        if not docker_copy_to(container_id, str(sca_bin), "/tmp/codescan-sca"):
            error("docker copy of SCA binary failed")
            return 1
        if skills_tgz.is_file() and skills_tgz.stat().st_size > 0:
            if not docker_copy_to(container_id, str(skills_tgz),
                                  "/tmp/codescan-skills.tgz"):
                step_warn("docker copy of skills pack failed (optional)")
        else:
            info("No SCA skills pack (optional), continuing")

        rc, out, err = docker_exec(
            container_id, "bash -c " + shlex.quote(INSTALL_BOOTSTRAP),
            timeout_secs=900,
        )
        if rc != 0:
            error(f"SCA install bootstrap failed (exit={rc}): {(out or err)[-1200:]}")
            return 1
        step_ok("SCA install bootstrap ok")

        env_prefix = " ".join(
            shlex.quote(f"{key}={value}")
            for key, value in {
                "ARTEX_LLM_API_KEY": api_key,
                "ARTEX_LLM_BASE_URL": base_url,
                "ARTEX_LLM_MODEL": model,
                "ARTEX_LLM_PROVIDER": "anthropic",
                "ARTEX_LLM_PROXY": proxy_url,
                "CODESCAN_PORT": str(port),
            }.items()
        )
        rc, out, err = docker_exec(
            container_id,
            f"env {env_prefix} bash -c " + shlex.quote(RUN_BOOTSTRAP),
            timeout_secs=180,
        )
        if rc != 0:
            error(f"SCA start failed (exit={rc}): {(out or err)[-1200:]}")
            return 1

        deadline = time.monotonic() + timeout_secs
        healthy = False
        for _ in range(90):
            code, _out = _container_curl(container_id, "GET", "/api/health",
                                         port=port)
            if code == 200:
                healthy = True
                break
            if time.monotonic() > deadline:
                break
            time.sleep(2)
        if not healthy:
            error("SCA engine never became healthy")
            return 1
        step_ok("SCA engine healthy")

        password = secrets.token_urlsafe(16)
        _container_curl(container_id, "POST", "/api/auth/init",
                        {"username": "admin", "password": password}, port=port)
        code, out = _container_curl(
            container_id, "POST", "/api/auth/login",
            {"username": "admin", "password": password}, port=port,
        )
        login = _json_or_none(out)
        if code != 200 or not login or not login.get("token"):
            error(f"SCA login failed (HTTP {code}): {out[:300]}")
            return 1
        token = login["token"]

        code, out = _container_curl(
            container_id, "PUT", "/api/settings", {"workers": worker_count},
            token=token, port=port,
        )
        if code in (200, 201, 204):
            step_ok(f"SCA workers set to {worker_count}")
        else:
            warn(f"SCA worker setting failed (HTTP {code}): {out[:200]}")

        code, out = _container_curl(container_id, "POST", "/api/llm", {
            "provider": "anthropic",
            "model": model,
            "base_url": base_url,
            "proxy": proxy_url,
            "api_key": api_key,
        }, token=token, port=port)
        if code not in (200, 201):
            warn(f"SCA LLM profile save failed (HTTP {code}): {out[:300]}")
        else:
            info("SCA LLM profile persisted")

        step_run("Pack source tree")
        rc, out, err = docker_exec(
            container_id, "bash -c " + shlex.quote(
                _build_zip_cmd(work_dir, source_entries)),
            timeout_secs=900,
        )
        pack_out = ((out or "") + (err or "")).strip()
        if rc != 0:
            error(f"SCA source zip failed (exit={rc}): {pack_out[-800:]}")
            return 1
        packed_src = ""
        zip_bytes = 0
        for line in pack_out.splitlines():
            if line.startswith("SRC="):
                packed_src = line[len("SRC="):].strip()
            elif line.startswith("ZIPBYTES="):
                try:
                    zip_bytes = int(line[len("ZIPBYTES="):].strip())
                except ValueError:
                    pass
        step_ok(f"Source packed: {packed_src} ({zip_bytes} bytes)")

        upload_cmd = (
            "curl -sS -m 600 -w '\\n%{http_code}' "
            f"-H {shlex.quote('Authorization: Bearer ' + token)} "
            f"-F {shlex.quote('file=@' + SOURCE_ZIP + ';type=application/zip')} "
            f"http://127.0.0.1:{port}/api/tasks/upload"
        )
        rc, out, err = docker_exec(container_id, upload_cmd, timeout_secs=620)
        raw = (out or "") + (err or "")
        body_text, _, status_text = raw.rpartition("\n")
        upload = _json_or_none(body_text)
        try:
            status_i = int(status_text.strip())
        except ValueError:
            status_i = 0
        if status_i not in (200, 201) or not upload or not upload.get("upload_id"):
            error(f"SCA upload failed (HTTP {status_i}): {raw[:400]}")
            return 1
        upload_id = upload["upload_id"]
        step_ok(f"Source uploaded ({upload.get('file_count')} files, "
                f"{upload.get('total_bytes')} bytes), upload_id={upload_id}")

        goal = prompt + OPERATIONS_BLOCK.format(
            source_entries=", ".join(f"`{entry}`" for entry in source_entries),
            work_dir=work_dir,
            example_path=example_path,
        )
        if config.get("include_description", False) and meta.get("description"):
            goal += (
                "\n\n## 漏洞线索(benchmark 元数据)\n\n"
                + str(meta["description"])
                + "\n"
            )

        task_timeout = max(300, timeout_secs - 300)
        task_body: dict[str, object] = {
            "name": f"[secbench] {instance_id}",
            "description": goal,
            "goal": goal,
            "timeout_seconds": task_timeout,
            "upload_id": upload_id,
            "auto_start": True,
            "seed_first_intent": bool(config.get("seed_first_intent", False)),
        }
        code, out = _container_curl(container_id, "POST", "/api/tasks",
                                    task_body, token=token, port=port,
                                    timeout=120)
        created = _json_or_none(out)
        if code != 201 or not created or not created.get("id"):
            error(f"SCA create task failed (HTTP {code}): {out[:500]}")
            return 1
        task_id = created["id"]
        step_ok(f"SCA task #{task_id} created (timeout={task_timeout}s)")

        status = "unknown"
        last_status = ""
        while time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL)
            code, out = _container_curl(
                container_id, "GET", f"/api/tasks/{task_id}",
                token=token, port=port,
            )
            dto = _json_or_none(out) if code == 200 else None
            status = dto.get("status", "unknown") if dto else "unreachable"
            if status != last_status:
                info(f"SCA task #{task_id} status={status}")
                last_status = status
            if status in TERMINAL_STATUSES:
                break
        if status not in TERMINAL_STATUSES:
            step_warn(f"SCA deadline reached; cancelling task #{task_id}")
            _container_curl(
                container_id, "POST", f"/api/tasks/{task_id}/control",
                {"action": "cancel"}, token=token, port=port,
            )

        code, out = _container_curl(
            container_id, "GET", f"/api/exploration/findings?task={task_id}",
            token=token, port=port, timeout=120,
        )
        findings_text = out if out.strip() else "[]"
        (instance_outdir / "codescan_findings.json").write_text(
            findings_text, encoding="utf-8")
        findings_count = _findings_count(findings_text)

        (instance_outdir / "codescan_meta.json").write_text(
            json.dumps({
                "instance_id": instance_id,
                "engine": "codescan-artex",
                "image_name": image_name,
                "work_dir": work_dir,
                "source_entries": source_entries,
                "upload_id": upload_id,
                "codescan_task_id": task_id,
                "final_status": status,
                "findings_count": findings_count,
                "timeout_seconds": timeout_secs,
                "task_timeout_seconds": task_timeout,
                "worker_count": worker_count,
                "port": port,
                "model": model,
                "source_zip_bytes": zip_bytes,
                "upload_file_count": upload.get("file_count"),
                "upload_total_bytes": upload.get("total_bytes"),
            }, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        if docker_copy_from(container_id, ENGINE_LOG,
                            str(instance_outdir / "codescan_engine.log")):
            info("Collected SCA engine log")
        else:
            step_warn("SCA engine log not found")

        if findings_count > 0:
            step_ok(f"CodeScan findings: {findings_count} "
                    f"(status={status}, http={code})")
            return 0
        step_err(f"CodeScan produced no findings (status={status}, http={code})")
        return 1
    finally:
        _cleanup(container_name)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run CodeScan-Artex as a SEC-bench Pro source-audit agent")
    parser.add_argument("config", type=Path, help="Path to TOML config file")
    parser.add_argument("--no-tui", action="store_true")
    args = parser.parse_args()

    config = load_config(args.config)
    config.setdefault("project", "v8")
    images_dir = resolve_path(SCRIPT_DIR, config["images_dir"])
    run_outdir = resolve_path(SCRIPT_DIR, config["outdir"])
    prompt_template_path = resolve_path(SCRIPT_DIR, config["prompt_template"])
    instances = resolve_instances(config, images_dir)
    docker_preflight()

    return run_eval_loop(
        instances=instances,
        images_dir=images_dir,
        run_outdir=run_outdir,
        prompt_template_path=prompt_template_path,
        config=config,
        agent_label=f"codescan/{config.get('model', DEFAULT_MODEL)}",
        run_instance_fn=run_instance,
        use_tui=not args.no_tui,
        instance_meta_dir=images_dir,
    )


if __name__ == "__main__":
    sys.exit(main())
