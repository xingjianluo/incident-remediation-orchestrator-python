# 本地告警自动修复编排服务（Incident Remediation Orchestrator）

在现有 FastAPI 服务内实现的一套**本地告警自动修复编排能力**，用于验证多模块协作下的：

1. **策略判定**：事件按策略匹配修复流程。`priority` 数值小者优先，同一优先级内
   **条件限定得更具体的规则先命中**；若两条策略的优先级与具体度完全平手、无法
   稳定分出唯一最优，则作为**配置冲突明确拒绝**（`policy_conflict`），同一份输入
   无论跑多少次、策略在文件里怎么排，结果都一致。字段缺失、字段值非法、无匹配、
   策略冲突四类拒绝各自带可区分原因，绝不静默执行。
2. **执行状态管理**：重复/并发/重试提交只产生一次有效副作用（exactly-once）；
   进程崩溃重启后恢复到确定状态；取消、超时、部分失败不重复执行、不状态倒退。
   持续失败的动作在**尝试预算耗尽后收敛到确定的失败终态**，后台不会反复自动重跑，
   须经人工显式确认才能再试；重试只接着未完成的步骤走，已生效步骤绝不重来。
3. **权限与审批**：危险动作需要角色权限 + 人工审批，未授权 / 权限不足 / 审批过期一律拒绝且**不改变执行状态**；所有自动与人工迁移写仅追加审计日志。
4. **调度公平性**：待审批的危险事件与已经结束的执行**不会阻塞队首**，普通事件按
   提交顺序（FIFO）持续推进；多个事件并发提交、重复提交或重试时，每个事件仍只
   产生一次有效副作用。

不依赖任何外部服务或真实凭据；所有“修复动作”均为本地文件标记/本地计算，可离线重复运行。

---

## 1. 目录结构

```
main.py                 # 根入口，复用 app 包内的 FastAPI 应用
app/
  config.py             # 环境变量配置（路径、TTL、超时、worker 节拍、尝试预算）
  schemas.py            # 事件/策略/动作/执行/审批/ACL 数据模型与枚举
  errors.py             # 统一异常 + 可区分拒绝原因（PolicyConflict 专表配置冲突）
  policies.py           # 策略加载与确定性匹配（priority 升序, 具体度降序, id 升序）
  storage.py            # 原子 JSON 存储 + event_id 幂等索引 + 副作用台账
  actions.py            # 本地修复动作注册表（4 个内置模拟动作）
  audit.py              # 仅追加、带单调序列号、fsync 的审计事件
  executor.py           # 状态机：提交/审批/调度公平性/恢复/取消/超时/收敛重试
  api.py                # FastAPI 路由、异常->HTTP 映射、生命周期
  main.py               # uvicorn 启动入口 + 日志配置
config/
  policies.json         # 默认策略配置（含宽兜底 + 同优先级精细规则示例）
  acl.json              # 用户-角色-能力模型
tests/                  # 53 个 pytest 用例（精细匹配/真冲突/收敛重试/公平性/并发/崩溃恢复/权限审批/审计/端到端）
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
| `IRO_EXECUTION_TIMEOUT_SECONDS` | `30` | 从**首次启动**起的总截止时间（重试/人工确认续跑不延长） |
| `IRO_WORKER_TICK_SECONDS` | `0.02` | 后台 worker 轮询节拍 |
| `IRO_MAX_ATTEMPTS` | `3` | 单个执行的**尝试预算**：首次执行 + 显式重试的总轮次上限 |

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

### 匹配裁决：优先级 → 具体度 → 真冲突

一个事件可能同时命中"范围很宽的兜底规则"和"针对具体主机/标签的精细规则"。
系统按以下顺序裁决：

1. **优先级**：`priority` 升序，数值小者优先（原有语义不变）。
2. **条件具体度**：同一优先级内，条件限定得更具体的规则先命中。具体度按规则中
   实际出现的限定维度计分，全部为 AND：
   - 限定了 `event_type`：+1
   - 限定了 `source_prefix`：+1
   - 限定了 `severities`：+1
   - `labels` 中**每个**键值对：+1

   例如同时限定了事件类型、来源范围、严重级别和标签的规则（4 分），会胜过只
   限定事件类型的规则（1 分）。默认配置里 `disk-full-edge-host`（来源前缀+
   critical+标签，同优先级）就比 `disk-full-restart` 更具体。
3. **真冲突**：若排序后最优策略与紧随其后的候选在 `(priority, 具体度)` 上
   **完全相同**，说明不存在唯一最优——这属于配置冲突，系统**明确拒绝整个事件**
   （绝不靠 `policy_id` 字典序之类的隐式次序静默选一条执行）。拒绝原因固定为
   `policy_conflict`，`details.conflicting_policies` 给出全部平手策略（按 id
   排序），`details.candidate_policies` 给出完整命中顺序。

候选策略的完整有序列表仍写入审计 `event.accepted.details.candidate_policies`。
裁决只依赖策略内容与事件本身：**同一份输入无论跑多少次、策略在文件里如何排列，
结果都一致**（具体度平手时冲突集合也稳定）。

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

调用方需要分辨的**四类事件层拒绝**各自独立、HTTP 状态与 reason 都不同；
应用日志（`request rejected reason=...`）与审计（`event.rejected`）里均带原因：

| reason | 场景 | HTTP |
| --- | --- | --- |
| `missing_field` | 事件**少了必填内容**（必填字段缺失） | 422 |
| `invalid_event` | 字段值本身不合法（空串/非法枚举/类型错误/请求体非对象、非 JSON） | 422 |
| `policy_not_found` | 事件合法但**没有任何策略**命中 | 422 |
| `policy_conflict` | 命中的多条策略在优先级与具体度上**完全平手**（配置冲突） | 409 |
| `unauthorized` | 匿名或未登记用户 | 403 |
| `forbidden` | 角色能力不足 | 403 |
| `approver_not_allowed` | 审批人未知或无 approve 能力 | 403 |
| `approval_expired` | 审批已过期/已消费 | 状态保持，重新挂起 |
| `execution_not_found` | 执行不存在 | 404 |
| `invalid_state_transition` | 终态取消/重试、对非待审批执行授权等 | 409 |
| `retry_exhausted` | 失败尝试预算耗尽，未经人工 `confirmed` 不可再试 | 409 |
| `action_unknown` | 策略引用了未注册动作 | 403 |

> 注意：`missing_field` 与 `invalid_event` 都是 422，调用方应依据响应体里的
> `reason` 字段而非仅靠状态码区分；`policy_not_found`（422）与
> `policy_conflict`（409）在 HTTP 层也已分开。

---

## 5. 状态机语义

```
                         危险动作且待审批
   PENDING ───────────────────────────────► AWAITING_APPROVAL
     │                                           │ 审批补齐（不阻塞他人）
     │ run.start                                 ▼
     └──────────────────────────────────────► RUNNING ──┬──► COMPLETED
                                  ▲   │  │  │  │        ├──► PARTIAL_FAILED（continue_on_failure）
            崩溃恢复/显式重试续跑 ──┘   │  │  │  └────────► CANCELLED（动作边界协作取消）
                                     │  │  └───────────► TIMED_OUT（总截止时间，终态）
                                     │  └──────────────► FAILED（确定失败态，仅显式重试）
                                     │                       │ 预算耗尽
                                     │                       ▼
                                     │                 RETRY_EXHAUSTED（收敛终态）
                                     │                       │ 人工 confirmed
                                     └───────────────────────┘
                                     （崩溃后记录留在 RUNNING，重启自动恢复）
```

- **幂等**：以 `event_id` 为唯一键。重复/并发提交返回同一条执行记录（响应中 `created=false`），
  存储在进程锁内创建并原子落盘（temp 文件 + `os.replace` + fsync）。
- **Exactly-once 副作用**：每个步骤有稳定 `effect_key = "{execution_id}:{index}"`。
  动作执行后先写**仅追加副作用台账** `effects.jsonl`（fsync），再提交步骤状态。
  恢复/重试时若台账已有该键，则只把步骤修复为 `applied`，**绝不重新调用动作**。
- **崩溃恢复**：若进程在副作用落账后、步骤提交前崩溃，记录留在 `RUNNING`。
  新进程启动后 worker 优先拾取 `RUNNING` 执行，依据台账补齐状态后续跑剩余动作。
- **取消**：仅在尚未生效的动作边界生效；已经应用的动作不回滚；终态不可取消。
- **超时**：以执行**首次启动**时间设定截止时间，重试、恢复或人工确认续跑都不延长、
  不重置，防止绕过超时；超时为终态，已应用步骤保留。

### 失败收敛与重试语义（不被后台反复重跑）

- 一个执行带有**尝试预算** `max_attempts`（`IRO_MAX_ATTEMPTS`，默认 3），
  首次启动计第 1 次（`attempts_used=1`），每次显式重试递增，记录在执行快照里。
- 某个不可继续（`continue_on_failure=false`）的动作失败时：
  - 仍有预算 → 进入 **`FAILED`**：一个确定的失败状态。后台 worker **不会自动
    拾取 `FAILED`**，因此持续失败的动作不会在后台被无限重跑，只能由人工调用
    `POST /executions/{id}/retry` 显式重试；
  - 已用满预算 → 进入 **`RETRY_EXHAUSTED` 终态**，停止一切自动推进。
- **显式重试只接着没做完的部分走**：`applied` 步骤原封不动（台账兜底，绝不
  重放、不产生重复副作用），仅 `failed` 步骤重置为 `pending` 重新执行。
- **人工确认再开预算**：对 `RETRY_EXHAUSTED` 的普通重试会被拒绝
  （409 `retry_exhausted`，状态不变）；必须带 `{"confirmed": true}` 显式确认，
  系统才把尝试计数重置为 1 并重新排队（审计 `retry.confirmed`）。反复失败→确认
  →再试的循环中，每步副作用仍全局唯一。
- 每次失败、每次重试、预算耗尽、人工确认都有审计条目
  （`step.failed` / `run.failed` / `run.retry` / `run.exhausted` /
  `retry.confirmed`），条目 `details` 带 `attempt`、`attempts_used`、
  `max_attempts`，失败次数与每次状态变化都可追溯。
- **部分失败**：`continue_on_failure=true` 时失败动作标记 `failed` 但继续，
  最终态 `partial_failed`（终态）。

### 调度公平性（不互相拖累）

worker 每轮按以下规则挑选**一个**执行推进：

1. `RUNNING`（崩溃恢复）与 `PENDING`（含显式重试后重新排队）可被调度，统一按
   **`(created_at, id)` FIFO**；
2. `AWAITING_APPROVAL` 的记录**只有在审批全部有效时才参与调度**；审批未齐时
   直接**跳过**而不是占住队首——因此系统里长期挂着待审批的危险事件，也不会
   挡住它之后提交的普通事件；
3. `FAILED` / `RETRY_EXHAUSTED` / 其他终态**完全不参与自动调度**，已结束的
   执行同样不会拖累后续事件；
4. 危险事件审批补齐后（或失败执行被显式重试后）会重新进入 FIFO 队列，按序推进。

边界：单条执行在动作执行期间仍持有存储锁（动作均为快速本地操作）；公平性保证的
是"不被待审批/已结束执行长期阻塞"，而不是抢占一个正在执行中的动作。

---

## 6. HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/events` | 提交告警（202；重复提交 200/202，`created=false`） |
| `GET` | `/executions` | 列出全部执行 |
| `GET` | `/executions/{id}` | 查询执行与每步状态 |
| `POST` | `/executions/{id}/approvals` | 人工授权危险动作 `{"granted_by":"alice","ttl_seconds":600}` |
| `POST` | `/executions/{id}/retry` | 显式重试 `{"requested_by":"carol"}`；对 `retry_exhausted` 终态须 `{"requested_by":"alice","confirmed":true}` |
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
  event_id=evt-001 policy=disk-full-edge-host candidates=['disk-full-edge-host', ...] accepted execution_id=exec-... state=pending
  execution_id=exec-... event_id=evt-001 transition running -> retry_exhausted reason=step 1 (...) failed: ...
  request rejected reason=policy_conflict details={'conflicting_policies': [...], ...}
  request rejected reason=missing_field details={...}
  execution_id=exec-... manual confirmation by=alice reopens attempt budget
  ```

- 审计日志：`var/log/audit.log`，JSONL，仅追加。字段：
  `seq`（单调递增、连续、不重号）、`ts`、`kind`、`execution_id`、`event_id`、
  `actor`、`from_state`、`to_state`、`policy_id`、`reason`、`details`。
  覆盖 `event.accepted`、`event.rejected`（reason 可为 `policy_not_found` /
  `policy_conflict`）、`submit.duplicate`、
  `run.start/finished/failed/exhausted/retry/timeout/cancelled`、
  `retry.confirmed`、
  `approval.granted/denied/required/complete/missing`、`step.applied/failed/recovered/crash_injected`、`cancel.requested`。
  启动时按已有行数重建序列号，因此并发追加和进程重启后都不会错序或重号。

---

## 8. 本地验证（可重复执行）

```bash
# 全部 53 个用例：
uv run pytest -q

# 查看本轮新增行为覆盖了哪些场景（用例名即场景名；项目默认 addopts=-q，需覆盖）：
uv run pytest tests/test_feature_b.py -o addopts="-v"
# 精细匹配/真冲突：
#   test_specificity_more_conditions_wins_within_same_priority
#   test_specificity_order_is_independent_of_file_order
#   test_equal_priority_equal_specificity_is_hard_conflict
#   test_policy_conflict_is_stable_regardless_of_file_order
# 拒绝原因可区分：
#   test_four_rejection_reasons_are_distinguishable
#   test_policy_conflict_over_api_is_separate_http_status
# 失败收敛与显式重试：
#   test_failed_execution_is_not_auto_rerun_by_worker
#   test_explicit_retry_resumes_remaining_step_without_duplicate_effect
#   test_repeated_retries_converge_to_terminal_after_budget
#   test_confirmed_retry_after_exhaustion_resumes_once_with_single_effect
#   test_rejected_retry_never_changes_state
# 调度公平性：
#   test_pending_events_advance_while_earlier_event_awaits_approval
#   test_failed_head_of_queue_does_not_block_later_events
#   test_fairness_holds_under_live_worker
# 并发/重试唯一副作用：
#   test_concurrent_distinct_events_each_have_single_effect
#   test_concurrent_retries_of_same_failed_execution_have_single_effect
#   test_retry_during_running_is_rejected_without_regression

# 真实服务端到端（含失败收敛 -> 人工确认续跑的 HTTP 全流程）：
uv run pytest tests/test_api_integration.py -o addopts="-v"
```

### 手工验证新行为

```bash
uv run uvicorn app.main:app --port 8000 &

# 1) 同优先级精细规则先命中：edge 主机命中 disk-full-edge-host（而非通用兜底）
curl -s -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' -d '{
  "event_id": "evt-edge", "event_type": "disk_full", "source": "host-edge-7",
  "severity": "critical", "labels": {"tier": "edge"}, "submitted_by": "carol"
}' | python -m json.tool | grep policy_id

# 2) 四类拒绝：缺字段(missing_field) / 值非法(invalid_event) /
#    无命中(policy_not_found, 422) / 策略冲突(policy_conflict, 409)
curl -s -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' \
  -d '{"event_id":"x"}'
curl -s -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' \
  -d '{"event_id":"x","event_type":"disk_full","source":"h","severity":"BAD"}'

# 3) 危险事件挂起时，普通事件照常完成（可连续提交多条观察 /executions）
curl -s -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' -d '{
  "event_id": "evt-danger", "event_type": "security_intrusion", "source": "fw-1",
  "severity": "critical", "submitted_by": "alice"}' >/dev/null
curl -s -X POST http://127.0.0.1:8000/events -H 'Content-Type: application/json' -d '{
  "event_id": "evt-normal", "event_type": "disk_full", "source": "host-1",
  "severity": "warning", "submitted_by": "carol"}' >/dev/null
curl -s http://127.0.0.1:8000/executions | python -m json.tool

# 4) 失败收敛：给策略动作配 {"fail": true} 后反复
#    POST /executions/{id}/retry，观察 failed -> retry_exhausted；
#    再带 {"confirmed": true} 人工确认续跑。

# 证据：
tail -f var/log/app.log var/log/audit.log
cat var/data/effects.jsonl   # 副作用台账：每个 effect_key 全局唯一
```

失败预算可用 `IRO_MAX_ATTEMPTS` 调整（例如快速演示耗尽：`IRO_MAX_ATTEMPTS=2`）。

测试全部使用临时目录与可控时钟（不访问网络、不使用真实凭据），
崩溃恢复用例通过动作内的 `crash_after_effect` 注入确定性故障，并以
“新建 Store/Executor 读取同一磁盘文件”模拟进程重启，可无限次重复运行。
调度公平性用例同时覆盖手工 tick（确定性）与真实后台 worker（端到端）。
