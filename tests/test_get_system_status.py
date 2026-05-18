"""mcp_server.server._compute_system_status の単体テスト。

具体値は環境依存なので、構造と型・範囲のみ assert する。
"""
from __future__ import annotations

from mcp_server import server as srv


def test_system_status_structure() -> None:
    """返却 dict の構造とフィールド型・範囲を確認する。"""
    result = srv._compute_system_status(services=("nonexistent_xyz_service",))

    # CPU
    assert isinstance(result["cpu_percent"], (int, float))
    assert 0 <= result["cpu_percent"] <= 100

    # load average
    assert "load_average" in result
    for k in ("1m", "5m", "15m"):
        assert k in result["load_average"]
        assert isinstance(result["load_average"][k], (int, float))
        assert result["load_average"][k] >= 0

    # memory
    assert result["memory"]["total_gb"] > 0
    assert 0 <= result["memory"]["percent"] <= 100
    assert result["memory"]["available_gb"] <= result["memory"]["total_gb"]

    # swap (zero がありうるので >= 0)
    assert result["swap"]["total_gb"] >= 0
    assert 0 <= result["swap"]["percent"] <= 100

    # disk
    assert result["disk_root"]["total_gb"] > 0
    assert result["disk_root"]["free_gb"] >= 0
    assert 0 <= result["disk_root"]["percent"] <= 100

    # uptime
    assert isinstance(result["uptime_seconds"], int)
    assert result["uptime_seconds"] >= 0

    # services: 存在しないユニットは inactive/unknown/failed
    assert result["services"]["nonexistent_xyz_service"] in (
        "inactive",
        "unknown",
        "failed",
    )


def test_systemctl_is_active_unknown_for_nonexistent() -> None:
    """実在しないユニット名で is-active が落ちないこと。"""
    state = srv._systemctl_is_active("absolutely_not_a_real_service_xyz")
    assert state in ("inactive", "unknown", "failed")


def test_default_services_list_is_tuple() -> None:
    """誤って書き換えできないよう DEFAULT_SERVICES は tuple であること。"""
    assert isinstance(srv.DEFAULT_SERVICES, tuple)
    assert "ssh" in srv.DEFAULT_SERVICES
