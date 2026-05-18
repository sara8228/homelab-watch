"""mcp_server.server._compute_ssh_failures の単体テスト。"""
from __future__ import annotations

import gzip
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


# --- Week 1 fixtures + tests ---


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
    assert result["files_read"] == 1
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


# --- Week 2 PR2: ローテート対応 + 年跨ぎ ---


@pytest.fixture
def fake_auth_log_with_rotation(tmp_path: Path) -> Path:
    """auth.log + auth.log.1 (plain) + auth.log.2.gz の 3 段ローテート構成。"""
    now = datetime.now()
    main = [
        _fmt(now - timedelta(hours=1), "u1", "203.0.113.10"),
        _fmt(now - timedelta(hours=3), "u2", "203.0.113.42"),
    ]
    rotated1 = [
        _fmt(now - timedelta(hours=50), "u3", "198.51.100.1"),
        _fmt(now - timedelta(hours=60), "u4", "198.51.100.2"),
    ]
    rotated_gz = [
        _fmt(now - timedelta(hours=200), "u5", "192.0.2.1"),
    ]
    auth_log = tmp_path / "auth.log"
    auth_log.write_text("\n".join(main) + "\n")
    (tmp_path / "auth.log.1").write_text("\n".join(rotated1) + "\n")
    with gzip.open(tmp_path / "auth.log.2.gz", "wt") as f:
        f.write("\n".join(rotated_gz) + "\n")
    return auth_log


def test_rotation_24h_only_reads_main_entries(
    fake_auth_log_with_rotation: Path,
) -> None:
    """24h 窓では auth.log 本体の 2 件のみ集計 (ローテートはエントリ時刻が範囲外)。"""
    result = srv._compute_ssh_failures(
        hours=24, auth_log=fake_auth_log_with_rotation
    )
    assert result["total_failures"] == 2
    assert result["files_read"] == 3  # ローテートも開く


def test_rotation_72h_includes_rotated_plain(
    fake_auth_log_with_rotation: Path,
) -> None:
    """72h 窓では auth.log.1 (plain) のエントリも拾う。"""
    result = srv._compute_ssh_failures(
        hours=72, auth_log=fake_auth_log_with_rotation
    )
    assert result["total_failures"] == 4  # main 2 + rotated1 2


def test_rotation_240h_includes_gz(
    fake_auth_log_with_rotation: Path,
) -> None:
    """240h 窓では gz ローテートも解凍して拾う。"""
    result = srv._compute_ssh_failures(
        hours=240, auth_log=fake_auth_log_with_rotation
    )
    assert result["total_failures"] == 5


def test_year_crossing(tmp_path: Path) -> None:
    """now=Jan 2 のとき Dec 31 のエントリを前年扱いで cutoff 比較する。"""
    now = datetime(2026, 1, 2, 12, 0, 0)
    log = tmp_path / "auth.log"
    log.write_text(
        "Dec 31 23:00:00 ubuntu-lab sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
        "Jan  1 00:30:00 ubuntu-lab sshd[2]: Failed password for admin from 1.2.3.4 port 22 ssh2\n"
        "Jan  2 11:00:00 ubuntu-lab sshd[3]: Failed password for root from 1.2.3.4 port 22 ssh2\n"
    )
    # 24h 窓: cutoff=Jan 1 12:00 → Jan 2 11:00 のみ
    r24 = srv._compute_ssh_failures(hours=24, auth_log=log, now=now)
    assert r24["total_failures"] == 1
    # 48h 窓: cutoff=Dec 31 12:00 (前年) → 3 件すべて
    r48 = srv._compute_ssh_failures(hours=48, auth_log=log, now=now)
    assert r48["total_failures"] == 3


def test_list_auth_log_files_handles_missing_main(tmp_path: Path) -> None:
    """auth.log 本体が無くてもローテートだけあれば拾える (logrotate 直後想定)。"""
    (tmp_path / "auth.log.1").write_text("dummy\n")
    files = srv._list_auth_log_files(tmp_path / "auth.log")
    assert files == [tmp_path / "auth.log.1"]
