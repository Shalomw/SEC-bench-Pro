# SEC-bench Pro 运行脚本

这些脚本按 ubuntu22 的运行布局编写：

- 仓库：`~/Projects/secbench-artex`
- LLM/判分密钥：`~/Projects/egrun/.secrets/env`
- ARTEX zip：`$HOME/Projects/secbench-artex/artex-fork-linux-amd64.zip`，
  回退到 `/tmp/artex-fork-linux-amd64.zip`

任务文件格式为 `<v8|sm> <instance_id>`，`#` 开头为注释。

| 脚本 | 用途 |
|---|---|
| `run_secbench_concurrency_a.sh` | 并发 A 组：每题生成独立 TOML，并行跑 `harness/eval_artex.py` |
| `run_codescan_concurrency_a.sh` | 并发 A 组：并行跑 `harness/eval_codescan.py`（findings-only） |
| `run_grade_concurrency_a.sh` | 调官方 harness 对并发 A 组输出判分 |
| `prepull_*.sh` / `chain_prepull_run.sh` | 镜像预拉与预拉后串行运行 |
| `tasks_concurrency_a_*.txt` | 并发 A 组 wave 1/2、重试与重新排队任务 |
