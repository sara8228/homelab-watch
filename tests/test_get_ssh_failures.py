"""mcp_server.server._compute_ssh_failures の単体テスト。"""
from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest

from mcp_server import server as srv


def _fmt(dt: datetime, user: str, ip: str) -> str:
    """auth.log 風の 1 行を組み立てる (テスト用)。"""
    return (
        f"{dt.strftime('%b %d %H:%M:%S')} ubuntu-lab "
        f"sshd[123]: Failed password for {user} from {ip} port 22 ssh2"
    )


@pytest.fixture
def fake_auth_log(tmp_path: Path) -> Path:
    """24h 窓内 3 件 + 窓外 1 件 + ノイズ 1 行 の合成 auth.log。"""
    now = datetime.now()
    lines = [
        _fmt(now - timedelta(minutes=5), "root", "203.0.113.10"),
        _fmt(now - timedelta(minutes=10), "admin", "203.0.113.42"),
        _fmt(now - timedelta(hours=2), "root", "198.51.100.1"),
        _fmt(now - timedelta(hours=30), "olduser", "192.0.2.1"),
        "May 17 12:00:00 ubuntu-lab CRON[42]: unrelated entry",
    ]
    p = tmp_path / "auth.log"
    p.write_text("\n".join(lines) + "\n")
    return p


def test_aggregates_within_window(fake_auth_log: Path) -> None:
    """過去 24h 内の Failed password 3 件が /24 集計される。"""
    result = srv._compute_ssh_failures(hours=24, auth_log=fake_auth_log)
    assert result["total_failures"] == 3
    assert result["parse_errors"] == 0
    subnets = {s["subnet"]: s["count"] for s in result["top_source_subnets"]}
    assert subnets["203.0.113.0/24"] == 2
    assert subnets["198.51.100.0/24"] == 1


def test_wider_window_includes_older(fake_auth_log: Path) -> None:
    """窓を 48h に広げると 24h 外も拾う。"""
    result = srv._compute_ssh_failures(hours=48, auth_log=fake_auth_log)
    assert result["total_failures"] == 4
    subnets = {s["subnet"]: s["count"] for s in result["top_source_subnets"]}
    assert subnets["192.0.2.0/24"] == 1


def test_missing_auth_log_returns_error(tmp_path: Path) -> None:
    """auth.log が無いケースは error フィールドを返す。"""
    missing = tmp_path / "does_not_exist.log"
    result = srv._compute_ssh_failures(hours=24, auth_log=missing)
    assert "error" in result
    assert result["hours"] == 24


def test_mask_ipv4_to_slash24() -> None:
    """マスキング関数の境界条件。"""
    assert srv._mask_ipv4_to_slash24("192.168.1.50") == "192.168.1.0/24"
    assert srv._mask_ipv4_to_slash24("0.0.0.0") == "0.0.0.0/24"
    assert srv._mask_ipv4_to_slash24("not.an.ip.address") == "not.an.ip.address"
    assert srv._mask_ipv4_to_slash24("::1") == "::1"
