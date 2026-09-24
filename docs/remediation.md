# 本地告警自动修复编排能力

本能力在现有 FastAPI 服务内实现（非独立脚本），用于本地验证多模块协作下的
**策略判定、执行状态管理、权限/审批控制与审计追溯**。不依赖任何外部服务或真实凭据，
所有“修复动作”只在本地目录产生确定性文件副作用。

- 服务入口：`main.py` → `remediation/app.py:create_app`
- HTTP 路由：`remediation/api.py`，前缀 `/api/remediation`
- 编排核心：`remediation/orchestrator.py`
- 持久化：SQLite（WAL），默认 `data/remediation.db`
- 本地副作用目录：默认 `data/effects/<event_id>/`

---

## 1. 策略配置

策略文件为 JSON，路径由环境变量 `REMEDIATION_POLICY_FILE` 指定，默认
`config/policies.json`，随仓库附带一份可用示例。

```json
{
  "policies": [
    {
      "policy_id": "disk-cleanup-auto",
      "priority": 100,
      "description": "可选说明",
      "match": { "source": "host-a", "alert_type": "disk_full", "severity_min": "high" },
      "actions": [
        { "name": "write-marker", "action": "write_file",
          "params": {"filename": "m.txt", "content": "go"}, "dangerous": false },
        { "name": "restart-log-service", "action": "restart_service",
          "params": {"service": "log-agent"},
          "dangerous": true, "required_role": "admin" }
      ]
    }
  ]
}
```

### 匹配键（`match`）

| 键 | 含义 |
|---|---|
| `source` | 事件来源，精确相等 |
| `alert_type` | 告警类型，精确相等 |
| `severity` | 严重级别，精确相等（`info/low/medium/high/critical`） |
| `severity_min` | 最低严重级别（含），按 `info<low<medium<high<critical` 比较 |

### 稳定、可复现的优先级裁决

同时匹配多条策略时，按以下**全序键**选出唯一策略，任何输入下结果相同：

1. `priority` 数值大者优先；
2. `priority` 相同，匹配条件更“具体”者优先（条件字段数多 > 指定 severity >
   指定 severity_min）；
3. 仍相同则按 `policy_id` 字典序。

若最高分出现并列（priority 与特异度都相同），判定为 **策略冲突**，服务返回
`POLICY_CONFLICT` 并将事件落为 `REJECTED`，**不执行任何动作**。冲突原因中列出
按字典序排序的冲突策略 ID，保证可复现。请通过调整 `priority` 或匹配条件消解冲突。

### 内置动作类型（`action`）

| 类型 | 说明 | 关键参数 |
|---|---|---|
| `noop` | 无副作用，仅记录 | — |
| `write_file` | 在事件目录内原子写文件（禁止绝对路径/`..`） | `filename`, `content` |
| `restart_service` | 不做真实重启，写入确定性重启记录 JSON | `service` |
| `simulate_fail` | 确定性失败，用于验证部分失败/失败语义 | `message` |

动作以固定文件为产物并使用临时文件 + `os.replace` 原子落盘，因此**重放结果幂等**。
策略引用了不存在的动作类型会在启动时以 `CONFIG_INVALID` 拒绝启动。

---

## 2. 权限与审批模型

调用方身份通过 HTTP 头传递（本地验证用，无真实凭据系统）：

- `X-Actor`：主体名；缺失即 `UNAUTHENTICATED`（401）。
- `X-Actor-Roles`：逗号分隔角色，缺省视为 `viewer`。

角色层级（高等级隐含低等级权限）：

```
admin    ⊇ operator ⊇ viewer
```

| 操作 | 最低角色 | 说明 |
|---|---|---|
| 提交事件 | viewer | 未认证直接拒绝，且不落任何执行状态 |
| 取消执行 | operator | 仅非终态可取消 |
| 审批危险动作 | admin | 仅 `WAITING_APPROVAL` 可审批 |

### 审批与 TTL

- 策略中任一动作 `dangerous: true`，事件在执行前进入 `WAITING_APPROVAL`，
  返回 `APPROVAL_REQUIRED`，不会自动执行。
- admin 审批通过后写入审批人、`approval_seq` 与过期时间
  （`now + REMEDIATION_APPROVAL_TTL_SECONDS`，默认 300 秒），随后自动继续执行。
- 审批在执行前已过期则拒绝为 `APPROVAL_EXPIRED`（HTTP 410）并落 `REJECTED`，
  **不产生危险动作副作用**。
- 越权审批、对非待审批状态审批、对终态取消等操作一律拒绝，
  **执行状态保持不变**；所有拒绝尝试也写入审计（`APPROVE_DENIED`/`CANCEL_DENIED`）。

---

## 3. 状态机语义

```
                 ┌─────────────────────────── 拒绝（无副作用） ───────────────────────────┐
                 │                                                                       │
 PENDING ──► WAITING_APPROVAL ──审批──► RUNNING ──全部成功──► COMPLETED
   │             │  │  ▲                   │  ├──部分成功──► PARTIALLY_FAILED
   │             │  │  └────审批过期────────┤  ├──全部失败──► FAILED
   │             │  └────────取消/超时/过期─┴──┼──取消──────► CANCELLED
   │             └──────────────────────────► ├──超过截止──► TIMED_OUT
   └────取消/超时────────────────────────────► └────────────►（以上均为终态）
 PENDING 无匹配/冲突 ──► REJECTED（终态）
```

- **终态**：`COMPLETED / PARTIALLY_FAILED / FAILED / CANCELLED / TIMED_OUT / REJECTED`。
  终态不接受任何迁移（重复审批/取消返回 409，状态不倒退）。
- **非法迁移**由集中式状态机 `remediation/state_machine.py` 拒绝
  （`INVALID_TRANSITION`），并以 version 乐观锁防止并发覆盖。
- **部分失败**：动作按顺序执行，首个失败即停止；已有成功步骤则
  `PARTIALLY_FAILED`，否则 `FAILED`。失败动作不自动重试，避免重复副作用。
- **超时**：进入 `RUNNING` 时设置整体截止时间
  （`REMEDIATION_STEP_TIMEOUT_SECONDS`，默认 30s），每个动作前检查，超时落
  `TIMED_OUT`。
- **取消**：`PENDING/WAITING_APPROVAL/RUNNING` 可被 operator 取消为 `CANCELLED`。

### 幂等、并发与恰好一次

- 事件以 `event_id` 为幂等键：重复/并发提交通过
  `INSERT OR IGNORE` 决出唯一创建者，其余请求返回同一记录且
  `duplicate=true`（HTTP 200），不重复执行。
- 每个 `event_id` 一把进程内互斥锁，串行化该事件的全部迁移；持久化层 version
  乐观锁作为第二道防线。
- 执行采用“**先落当前步骤位置，再执行动作，再落完成标记**”：
  - 正常完成后重复提交只返回终态；
  - 若进程在“副作用已完成但完成标记未落盘”的窗口崩溃，重启恢复时该步骤会被
    **重放**；因动作产物固定且原子覆盖，逻辑副作用仍恰好一次，随后继续完成剩余步骤。
- **崩溃恢复**：服务启动（FastAPI lifespan）时自动扫描所有非终态记录
  `recover_all()`：等待审批的保持等待（审批过期则拒绝），运行中的从
  `current_index` 与 `completed_actions` 确定性恢复。

### 审计

每次接收、策略裁决、状态迁移、审批、取消、拒绝都写一条审计（SQLite
`audit_log` 表）：同一事件内 `seq` 从 1 连续递增，UNIQUE 约束保证不重号，
追加写保证不乱序、不丢失；同时输出结构化 JSON 日志，包含事件标识、
策略判定、状态迁移、操作人与拒绝原因。查询：
`GET /api/remediation/executions/{event_id}/audit`。

---

## 4. HTTP 接口

| 方法 & 路径 | 说明 |
|---|---|
| `POST /api/remediation/events` | 提交告警事件（头 `X-Actor`/`X-Actor-Roles`） |
| `GET  /api/remediation/executions/{event_id}` | 查询执行状态 |
| `POST /api/remediation/executions/{event_id}/approve` | admin 审批并续跑 |
| `POST /api/remediation/executions/{event_id}/cancel` | operator 取消 |
| `GET  /api/remediation/executions/{event_id}/audit` | 审计流水 |
| `GET /healthz` `/` | 健康检查 |

拒绝响应统一形如：

```json
{"rejected": true, "reason": "NO_MATCHING_POLICY", "message": "..."}
```

拒绝原因码（`reason`）：`MALFORMED_EVENT`(400)、`MISSING_FIELD`(400)、
`NO_MATCHING_POLICY`(422)、`POLICY_CONFLICT`(422)、`UNAUTHENTICATED`(401)、
`FORBIDDEN`(403)、`PERMISSION_DENIED`(403)、`APPROVAL_REQUIRED`(409)、
`APPROVAL_EXPIRED`(410)、`ILLEGAL_STATE`/`INVALID_TRANSITION`(409)、
`EXECUTION_NOT_FOUND`(404)、`CONFIG_INVALID`(500)。

---

## 5. 本地验证方法

仅需仓库已有依赖（FastAPI + pytest），可离线重复执行。

### 运行测试（覆盖全部要求场景）

```bash
uv sync
uv run pytest
```

测试覆盖：

- `tests/test_policy_matching.py`：优先级、冲突稳定拒绝、无匹配、字段缺失；
- `tests/test_idempotency.py`：重复提交、8 线程并发提交、完成后重试、并发审批；
- `tests/test_recovery.py`：副作用后崩溃 + 重启恢复恰好一次、部分失败、超时终态；
- `tests/test_authz.py`：未授权/越权/审批过期不改变状态、审计连续不乱序；
- `tests/test_api.py`：HTTP 状态码、异常响应、服务重启后自动恢复。

### 手动端到端

```bash
rm -rf data
uv run uvicorn main:app --port 8000

# 提交（含危险动作 -> WAITING_APPROVAL）
curl -s -X POST localhost:8000/api/remediation/events \
  -H 'Content-Type: application/json' \
  -H 'X-Actor: op1' -H 'X-Actor-Roles: operator' \
  -d '{"event_id":"demo-1","source":"host-a","alert_type":"disk_full","severity":"high"}'

# 越权审批被拒（operator，403，状态不变）
curl -s -X POST localhost:8000/api/remediation/executions/demo-1/approve \
  -H 'X-Actor: op1' -H 'X-Actor-Roles: operator'

# admin 审批后自动完成
curl -s -X POST localhost:8000/api/remediation/executions/demo-1/approve \
  -H 'X-Actor: root' -H 'X-Actor-Roles: admin'

# 审计流水
curl -s localhost:8000/api/remediation/executions/demo-1/audit

# 查看本地副作用
find data/effects -type f
```

### 配置项（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `REMEDIATION_POLICY_FILE` | `config/policies.json` | 策略文件 |
| `REMEDIATION_DB_PATH` | `data/remediation.db` | SQLite 路径 |
| `REMEDIATION_EFFECTS_DIR` | `data/effects` | 本地副作用目录 |
| `REMEDIATION_APPROVAL_TTL_SECONDS` | `300` | 审批有效期 |
| `REMEDIATION_STEP_TIMEOUT_SECONDS` | `30` | 整体执行超时 |
| `REMEDIATION_MAX_EVENT_SIZE` | `65536` | 事件体大小上限（字节） |
| `REMEDIATION_LOG_LEVEL` | `INFO` | 日志级别 |
