"""mcp_server.server._compute_pending_updates の単体テスト (subprocess mock)。"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_server import server as srv


@dataclass
class FakeCompletedProcess:
    """subprocess.run の戻り値を模倣する最小 dataclass。"""
    stdout: str
    stderr: str = ""
    returncode: int = 0


def _install_fake_apt(monkeypatch: pytest.MonkeyPatch, stdout: str) -> None:
    """apt コマンドを fake し、shutil.which も apt が存在することに固定する。"""
    monkeypatch.setattr(srv.shutil, "which", lambda cmd: "/usr/bin/apt")
    monkeypatch.setattr(
        srv.subprocess,
        "run",
        lambda *a, **kw: FakeCompletedProcess(stdout=stdout),
    )


SAMPLE_MIXED = """Listing...
gcc-13/noble-updates 13.3.0-6ubuntu2~24.04.1 amd64 [upgradable from: 13.2.0-23ubuntu4]
libssl3t64/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
openssh-server/noble-security 1:9.6p1-3ubuntu13.5 amd64 [upgradable from: 1:9.6p1-3ubuntu13.4]
linux-image-generic/noble-updates 6.17.0.23.20 amd64 [upgradable from: 6.17.0.20.18]
linux-headers-generic/noble-updates 6.17.0.23.20 amd64 [upgradable from: 6.17.0.20.18]
linux-generic-hwe-24.04/noble-updates 6.17.0.23.20 amd64 [upgradable from: 6.17.0.20.18]
"""


def test_mixed_security_and_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    """通常 / security / kernel が混じる典型ケース。"""
    _install_fake_apt(monkeypatch, SAMPLE_MIXED)
    # cache age も決定論的に: 存在しないパスを渡して None になることを確認
    result = srv._compute_pending_updates(cache_path=Path("/nonexistent/path"))

    assert result["total"] == 6
    assert result["security_count"] == 2
    assert result["kernel_count"] == 3
    assert result["kernel_update_needed"] is True
    assert "libssl3t64" in result["security_packages"]
    assert "openssh-server" in result["security_packages"]
    assert "linux-image-generic" in result["kernel_packages"]
    assert "linux-headers-generic" in result["kernel_packages"]
    assert "linux-generic-hwe-24.04" in result["kernel_packages"]
    assert result["cache_age_seconds"] is None


def test_security_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """security update のみ、kernel なし。"""
    _install_fake_apt(monkeypatch, """Listing...
libssl3t64/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]
""")
    result = srv._compute_pending_updates(cache_path=Path("/nonexistent"))
    assert result["total"] == 1
    assert result["security_count"] == 1
    assert result["kernel_update_needed"] is False
    assert result["kernel_packages"] == []


def test_empty_upgradable(monkeypatch: pytest.MonkeyPatch) -> None:
    """更新可能パッケージなし (Listing... 行のみ)。"""
    _install_fake_apt(monkeypatch, "Listing...\n")
    result = srv._compute_pending_updates(cache_path=Path("/nonexistent"))
    assert result["total"] == 0
    assert result["security_count"] == 0
    assert result["kernel_update_needed"] is False


def test_apt_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """apt コマンドが PATH に無い環境では error を返す。"""
    monkeypatch.setattr(srv.shutil, "which", lambda cmd: None)
    result = srv._compute_pending_updates(cache_path=Path("/nonexistent"))
    assert "error" in result
    assert result["total"] == 0


def test_is_kernel_package() -> None:
    """カーネル判定の境界条件 (linux-* を広く allow + 既知非カーネルを除外)。"""
    # ストレートな kernel パッケージ
    assert srv._is_kernel_package("linux-image-6.17.0-23-generic") is True
    assert srv._is_kernel_package("linux-modules-6.17.0-23-generic") is True
    assert srv._is_kernel_package("linux-headers-generic") is True
    assert srv._is_kernel_package("linux-base") is True
    # メタパッケージ (variant 含む)
    assert srv._is_kernel_package("linux-generic") is True
    assert srv._is_kernel_package("linux-generic-hwe-24.04") is True
    assert srv._is_kernel_package("linux-image-generic-hwe-24.04") is True
    assert srv._is_kernel_package("linux-aws-cloud-tools") is True  # クラウド variant
    # 非カーネル (denylist)
    assert srv._is_kernel_package("linux-libc-dev") is False
    # linux- プレフィックス以外
    assert srv._is_kernel_package("gcc-13") is False
    assert srv._is_kernel_package("libssl3t64") is False


def test_parse_handles_malformed_lines() -> None:
    """壊れた行・header 行・空行は無視される。"""
    assert srv._parse_apt_upgradable_line("Listing...") is None
    assert srv._parse_apt_upgradable_line("") is None
    assert srv._parse_apt_upgradable_line("garbage no slash") is None
    assert srv._parse_apt_upgradable_line("pkg/source nover arch") is None  # no "from:"


def test_cache_age_seconds_with_file(tmp_path: Path) -> None:
    """実ファイル mtime からの経過秒が返される。"""
    f = tmp_path / "pkgcache.bin"
    f.write_text("x")
    age = srv._apt_cache_age_seconds(f)
    assert age is not None
    assert age >= 0
    assert age < 60  # 直前に作成したので 60 秒未満
