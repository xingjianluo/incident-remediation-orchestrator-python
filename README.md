# Incident Remediation Orchestrator（本地告警自动修复编排）

在现有 FastAPI 服务内实现本地告警的策略匹配、修复执行状态机、危险动作权限/审批
与审计追溯。纯本地运行，不依赖外部服务或真实凭据。

- 启动：`uv run uvicorn main:app --port 8000`
- 测试：`uv run pytest`（30 个用例，覆盖策略冲突、重复/并发提交、故障重启、
  权限与审批边界）
- 详细说明：见 [docs/remediation.md](docs/remediation.md)
  （策略配置、权限审批模型、状态机语义、本地验证方法）
