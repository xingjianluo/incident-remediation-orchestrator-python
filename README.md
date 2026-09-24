# 本地告警自动修复编排服务（Incident Remediation Orchestrator）

在现有 FastAPI 服务内实现的一套**本地告警自动修复编排能力**，用于验证多模块协作下的：

1. **策略判定**：事件按策略匹配修复流程，冲突时优先级稳定可复现；字段缺失、无匹配、非法事件一律拒绝并返回可区分原因，绝不静默执行。
2. **执行状态管理**：重复/并发/重试提交只产生一次有效副作用（exactly-once）；进程崩溃重启后恢复到确定状态；取消、超时、部分失败不重复执行、不状态倒退。
3. **权限与审批**：危险动作需要角色权限 + 人工审批，未授权 / 权限不足 / 审批过期一律拒绝且**不改变执行状态**；所有自动与人工迁移写仅追加审计日志。

不依赖任何外部服务或真实凭据；所有“修复动作”均为本地文件标记/本地计算，可离线重复运行。

---

## 1. 目录结构

```
main.py                 # 根入口，复用 app 包内的 FastAPI 应用
app/
  config.py             # 环境变量配置（路径、TTL、超时、worker 节拍）
  schemas.py            # 事件/策略/动作/执行/审批/ACL 数据模型与枚举
  errors.py             # 统一异常 + 可区分拒绝原因 RejectReason
  policies.py           # 策略加载与确定性匹配（priority 升序, id 升序）
  storage.py            # 原子 JSON 存储 + event_id 幂等索引 + 副作用台账
  actions.py            # 本地修复动作注册表（4 个内置模拟动作）
  audit.py              # 仅追加、带单调序列号、fsync 的审计日志
  executor.py           # 状态机：提交/审批/调度/恢复/取消/超时/重试
  api.py                # FastAPI 路由、异常->HTTP 映射、生命周期
  main.py               # uvicorn 启动入口 + 日志配置
config/
  policies.json         # 默认策略配置
  acl.json              # 用户-角色-能力模型
tests/                  # 35 个 pytest 用例（冲突/并发/崩溃恢复/权限审批/审计/端到端）
```

---

## 2. 本地启动

需要 Python 3.14 与 [uv](https://docs.astral.sh/uv/)。

```bash
uv sync                 # 安装依赖（含开发依赖 pytest）
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
# 或
uv run python -m app.main
```

健康检查：

```bash
curl http://127.0.0.1:8000/health
```

### 环境变量（均有默认值）

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `IRO_BASE_DIR` | `.` | 配置/数据/日志根目录 |
| `IRO_DATA_DIR` | `$BASE/var/data` | store.json、effects.jsonl |
| `IRO_LOG_DIR` | `$BASE/var/log` | audit.log、app.log |
| `IRO_POLICY_FILE` | `config/policies.json` | 策略文件 |
| `IRO_ACL_FILE` | `config/acl.json` | 权限模型文件 |
| `IRO_APPROVAL_TTL_SECONDS` | `600` | 审批有效期 |
| `IRO_EXECUTION_TIMEOUT_SECONDS` | `30` | 从**首次启动**起的总截止时间（重试/恢复不延长） |
| `IRO_WORKER_TICK_SECONDS` | `0.02` | 后台 worker 轮询节拍 |

---

## 3. 策略配置（`config/policies.json`）

策略数组，字段：

- `id`：唯一策略标识（重复会导致加载失败）。
- `match`：匹配规则，全部条件为 AND：
  - `event_type`：精确匹配（缺省表示不限）
  - `source_prefix`：事件 `source` 前缀
  - `severities`：允许的严重级别集合（`info`/`warning`/`critical`）
  - `labels`：标签键值必须全部相等
- `priority`：**数值越小优先级越高**。
- `actions`：有序动作列表，至少一个。

### 冲突解决（稳定可复现）

一个事件可能命中多个策略。系统把全部命中策略按 `(priority 升序, policy_id 升序)`
排序，取第一条执行；候选策略的完整有序列表写入审计 `event.accepted.details.candidate_policies`。
同一份输入永远得到同一个结果，与策略在文件中的排列顺序无关。

### 动作定义

- `name`：`actions.py` 注册表中的动作（内置 `restart_service`、`clear_disk_cache`、`isolate_host`、`scale_workers`）。
- `risk`：`safe`（默认）或 `dangerous`（危险动作需要审批）。
- `required_role`：提交者必须具备的能力名（与 ACL 中角色能力对应）。
- `continue_on_failure`：动作失败后是否继续后续动作；为 `true` 时最终态为 `partial_failed`。
- `params`：动作参数。测试用 `{"fail": true}` 可确定性制造失败；
  `crash_after_effect: true` 可在“副作用落账后、步骤状态提交前”模拟进程崩溃，用于恢复演练。

---

## 4. 权限与审批模型（`config/acl.json`）

```json
{
  "users": {"alice": "admin", "carol": "operator", "dave": "viewer"},
  "roles": {
    "admin":    ["operator", "admin", "approve"],
    "operator": ["operator"],
    "viewer":   ["read"]
  }
}
```

- 提交事件时携带 `submitted_by`。系统先 `user -> role`，再校验 `role` 是否包含动作 `required_role` 能力。
- 未提供用户 / 用户不存在 → `unauthorized`（HTTP 403）。
- 角色能力不足（如 operator 提交需要 `admin` 的隔离动作）→ `forbidden`（HTTP 403）。
- 权限预检在创建执行记录**之前**：任一危险动作越权，整个事件被拒绝，**不产生任何执行状态或副作用**。
- 危险动作（`risk=dangerous`）额外需要人工审批：执行停在 `awaiting_approval`，
  由具备 `approve` 能力的角色调用授权接口，审批带 TTL，过期后必须重新授权。
- 审批在危险动作真正应用后被标记 `consumed`，一次性使用。
- 审批过期 / 审批人无 `approve` 能力 → 403 且执行状态保持不变（审计记录 `approval.denied` / `approval.missing`）。

### 拒绝原因（`RejectReason`，可区分、可断言）

| reason | 场景 | HTTP |
| --- | --- | --- |
| `invalid_event` | 字段缺失/空串/非法枚举（Pydantic 校验失败） | 422 |
| `policy_not_found` | 事件合法但无任何策略匹配 | 422 |
| `unauthorized` | 匿名或未登记用户 | 403 |
| `forbidden` | 角色能力不足 | 403 |
| `approver_not_allowed` | 审批人未知或无 approve 能力 | 403 |
| `approval_expired` | 审批已过期/已消费 | 状态保持，重新挂起 |
| `execution_not_found` | 执行不存在 | 404 |
| `invalid_state_transition` | 终态取消/重试、对非待审批执行授权等 | 409 |
| `action_unknown` | 策略引用了未注册动作 | 403 |

---

## 5. 状态机语义

```
                         危险动作且待审批
   PENDING ───────────────────────────────► AWAITING_APPROVAL
     │                                           │ 审批补齐
     │ run.start                                 ▼
     └──────────────────────────────────────► RUNNING ──┬──► COMPLETED
                                  ▲   │  │  │  │        ├──► PARTIAL_FAILED（continue_on_failure）
            崩溃恢复/重试续跑 ────┘   │  │  │  └────────► CANCELLED（动作边界协作取消）
                                     │  │  └───────────► TIMED_OUT（总截止时间，终态）
                                     │  └──────────────► FAILED（可 retry）
                                     └───────────────── （崩溃后记录留在 RUNNING，重启自动恢复）
```

- **幂等**：以 `event_id` 为唯一键。重复/并发提交返回同一条执行记录（响应中 `created=false`），
  存储在进程锁内创建并原子落盘（temp 文件 + `os.replace` + fsync）。
- **Exactly-once 副作用**：每个步骤有稳定 `effect_key = "{execution_id}:{index}"`。
  动作执行后先写**仅追加副作用台账** `effects.jsonl`（fsync），再提交步骤状态。
  恢复时若台账已有该键，则只把步骤修复为 `applied`，**绝不重新调用动作**。
- **崩溃恢复**：若进程在副作用落账后、步骤提交前崩溃，记录留在 `RUNNING`。
  新进程启动后 worker 优先拾取 `RUNNING` 执行，依据台账补齐状态后续跑剩余动作。
- **取消**：仅在尚未生效的动作边界生效；已经应用的动作不回滚；终态不可取消。
- **超时**：以执行**首次启动**时间设定截止时间，重试或恢复不延长、不重置，防止绕过超时；
  超时为终态，已应用步骤保留。
- **重试**：仅 `failed` 可显式重试；`failed` 步骤重置为 `pending`，
  `applied` 步骤保留且不会重放（台账兜底）。终态（completed/partial_failed/cancelled/timed_out）不可重试。
- **部分失败**：`continue_on_failure=true` 时失败动作标记 `failed` 但继续，最终态 `partial_failed`（终态）。

---

## 6. HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/events` | 提交告警（202；重复提交 200/202，`created=false`） |
| `GET` | `/executions` | 列出全部执行 |
| `GET` | `/executions/{id}` | 查询执行与每步状态 |
| `POST` | `/executions/{id}/approvals` | 人工授权危险动作 `{"granted_by":"alice","ttl_seconds":600}` |
| `POST` | `/executions/{id}/retry` | FAILED 后续跑 `{"requested_by":"carol"}` |
| `POST` | `/executions/{id}/cancel` | 请求取消 `{"requested_by":"carol"}` |
| `GET` | `/health` | 健康检查 |

示例：

```bash
curl -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' -d '{
  "event_id": "evt-001",
  "event_type": "disk_full",
  "source": "host-42",
  "severity": "critical",
  "submitted_by": "alice"
}'
```

---

## 7. 日志与审计

- 应用日志：`var/log/app.log`（同时输出到控制台），使用 `iro.*` logger。
  关键行包含**事件标识、命中策略与候选列表、状态迁移（from -> to）、拒绝原因**，例如：

  ```
  event_id=evt-001 policy=disk-full-restart candidates=['disk-full-restart', ...] accepted execution_id=exec-... state=pending
  execution_id=exec-... event_id=evt-001 transition running -> completed reason=all steps applied
  request rejected reason=approver_not_allowed details={...}
  ```

- 审计日志：`var/log/audit.log`，JSONL，仅追加。字段：
  `seq`（单调递增、连续、不重号）、`ts`、`kind`、`execution_id`、`event_id`、
  `actor`、`from_state`、`to_state`、`policy_id`、`reason`、`details`。
  覆盖 `event.accepted`、`event.rejected`、`submit.duplicate`、`run.start/finished/failed/timeout/cancelled/retry`、
  `approval.granted/denied/required/complete/missing`、`step.applied/failed/recovered/crash_injected`、`cancel.requested`。
  启动时按已有行数重建序列号，因此并发追加和进程重启后都不会错序或重号。

---

## 8. 本地验证（可重复执行）

```bash
# 全部 35 个用例：策略冲突 / 重复+并发提交 / 故障重启 exactly-once /
# 权限与审批边界 / 取消超时部分失败 / 审计连续性 / 真实服务端到端
uv run pytest -q

# 端到端手工验证
uv run uvicorn app.main:app --port 8000 &
# 见第 6 节 curl 示例；查看证据：
tail -f var/log/app.log var/log/audit.log
cat var/data/effects.jsonl   # 副作用台账：每个 effect_key 全局唯一
```

测试全部使用临时目录与可控时钟（不访问网络、不使用真实凭据），
崩溃恢复用例通过动作内的 `crash_after_effect` 注入确定性故障，并以
“新建 Store/Executor 读取同一磁盘文件”模拟进程重启，可无限次重复运行。
