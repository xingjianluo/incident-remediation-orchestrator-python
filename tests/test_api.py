"""HTTP 集成：验证接入 FastAPI 后的启动、异常处理、状态码与崩溃后重启恢复。"""
from __future__ import annotations


def test_health_and_root(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/").json()["service"] == "incident-remediation-orchestrator"


def test_submit_validation_errors(client):
    # 无身份
    r = client.post("/api/remediation/events", json={"event_id": "x"})
    assert r.status_code == 401 and r.json()["reason"] == "UNAUTHENTICATED"
    # 非法 JSON
    r = client.post(
        "/api/remediation/events",
        content=b"{not-json",
        headers={"Content-Type": "application/json", "X-Actor": "op1",
                 "X-Actor-Roles": "operator"},
    )
    assert r.status_code == 400 and r.json()["reason"] == "MALFORMED_EVENT"
    # 缺字段
    r = client.post(
        "/api/remediation/events",
        json={"event_id": "x", "source": "s"},
        headers={"X-Actor": "op1", "X-Actor-Roles": "operator"},
    )
    assert r.status_code == 400 and r.json()["reason"] == "MISSING_FIELD"
    # 非法 severity
    r = client.post(
        "/api/remediation/events",
        json={"event_id": "x", "source": "s", "alert_type": "t", "severity": "urgent"},
        headers={"X-Actor": "op1", "X-Actor-Roles": "operator"},
    )
    assert r.status_code == 400 and r.json()["reason"] == "MALFORMED_EVENT"


def test_policy_rejections_over_http(client):
    r = client.post(
        "/api/remediation/events",
        json={"event_id": "n1", "source": "zz", "alert_type": "zz", "severity": "low"},
        headers={"X-Actor": "op1", "X-Actor-Roles": "operator"},
    )
    assert r.status_code == 422 and r.json()["state"] == "REJECTED"
    assert r.json()["reject_reason"] == "NO_MATCHING_POLICY"

    r = client.post(
        "/api/remediation/events",
        json={"event_id": "c1", "source": "s", "alert_type": "ambiguous", "severity": "low"},
        headers={"X-Actor": "op1", "X-Actor-Roles": "operator"},
    )
    assert r.status_code == 422 and r.json()["reject_reason"] == "POLICY_CONFLICT"


def test_dangerous_flow_over_http(client):
    hdr = {"X-Actor": "op1", "X-Actor-Roles": "operator"}
    admin = {"X-Actor": "root", "X-Actor-Roles": "admin"}

    r = client.post(
        "/api/remediation/events",
        json={"event_id": "d1", "source": "host-a",
              "alert_type": "disk_full", "severity": "high"},
        headers=hdr,
    )
    assert r.status_code == 201 and r.json()["state"] == "WAITING_APPROVAL"

    # 重复提交 -> 200
    r2 = client.post(
        "/api/remediation/events",
        json={"event_id": "d1", "source": "host-a",
              "alert_type": "disk_full", "severity": "high"},
        headers=hdr,
    )
    assert r2.status_code == 200 and r2.json()["duplicate"] is True

    # 越权审批 -> 403，状态不变
    r3 = client.post("/api/remediation/executions/d1/approve", headers=hdr)
    assert r3.status_code == 403 and r3.json()["reason"] == "PERMISSION_DENIED"
    assert client.get("/api/remediation/executions/d1").json()["state"] == "WAITING_APPROVAL"

    # admin 审批 -> COMPLETED
    r4 = client.post("/api/remediation/executions/d1/approve", headers=admin)
    assert r4.status_code == 200 and r4.json()["state"] == "COMPLETED"

    # 审计可追溯
    audit = client.get("/api/remediation/executions/d1/audit").json()["entries"]
    seqs = [e["seq"] for e in audit]
    assert seqs == list(range(1, len(seqs) + 1))
    assert "APPROVE_DENIED" in [e["transition"] for e in audit]


def test_cancel_boundaries(client):
    hdr = {"X-Actor": "op1", "X-Actor-Roles": "operator"}
    client.post(
        "/api/remediation/events",
        json={"event_id": "k1", "source": "x",
              "alert_type": "service_down", "severity": "high"},
        headers=hdr,
    )
    r = client.post(
        "/api/remediation/executions/k1/cancel",
        headers={"X-Actor": "v", "X-Actor-Roles": "viewer"},
    )
    assert r.status_code == 403
    r = client.post("/api/remediation/executions/k1/cancel", headers=hdr)
    assert r.status_code == 200 and r.json()["state"] == "CANCELLED"
    r = client.post("/api/remediation/executions/k1/cancel", headers=hdr)
    assert r.status_code == 409
    assert client.get("/api/remediation/executions/missing").status_code == 404


def test_server_restart_recovers_state(paths, policy_file):
    """关闭并重新创建应用（模拟服务重启），非终态执行被恢复到确定状态。"""
    from fastapi.testclient import TestClient

    from remediation.actions import SimulatedCrash
    from remediation.app import create_app
    from remediation.config import Settings

    settings = Settings(
        policy_file=str(policy_file),
        db_path=str(paths / "data" / "restart.db"),
        effects_dir=str(paths / "effects-restart"),
        approval_ttl_seconds=300,
        step_timeout_seconds=30,
        log_level="ERROR",
    )

    with TestClient(create_app(settings)) as app1:
        # 直接在组件上注入崩溃点：安全动作 ack 副作用完成后崩溃
        app1.app.state.orchestrator.actions.crash_after.add("ack")
        try:
            app1.app.state.orchestrator.submit(
                {"event_id": "r1", "source": "host-a",
                 "alert_type": "noise-x", "severity": "low"},
                __import__("remediation.authz", fromlist=["Actor"]).Actor.parse("op", "operator"),
            )
            raise AssertionError("应模拟崩溃")
        except SimulatedCrash:
            pass

    # 全新应用实例、同一数据库：启动 lifespan 自动恢复
    with TestClient(create_app(settings)) as app2:
        status = app2.app.state.orchestrator.get_status("r1")
        assert status["state"] == "COMPLETED"
        assert status["completed_actions"] == ["ack"]
