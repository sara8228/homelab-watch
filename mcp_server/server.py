"""homelab-watch MCP サーバー。

提供する read-only ツール:
- get_ssh_failures: auth.log + ローテートから過去 N 時間の SSH 失敗を集計 (/24 マスク)
- get_system_status: CPU / load / memory / disk / 主要サービス状態を返す
- get_pending_updates: apt の更新可能パッケージサマリ (security/kernel フラグ付き)
"""
from __future__ import annotations

import gzip
import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

import psutil
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

AUTH_LOG = Path(os.environ.get("HOMELAB_WATCH_AUTH_LOG", "/var/log/auth.log"))

_FAILED_PASSWORD_RE = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+).*"
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+)"
)

mcp = FastMCP("homelab-watch")


def _mask_ipv4_to_slash24(ip: str) -> str:
    """IPv4 の第 4 オクテットを 0 に丸めて /24 表記に変換する。

    形式不正な値や IPv6 はそのまま返す (best-effort)。
    """
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip


def _list_auth_log_files(auth_log: Path) -> list[Path]:
    """auth.log + ローテート済みファイル (.1, .2.gz, ...) を新→旧順で列挙。

    auth_log 本体が無くてもローテートファイルがあれば返す
    (logrotate 直後の一瞬を許容)。
    最大 31 ローテートまで探索。
    """
    files: list[Path] = []
    if auth_log.exists():
        files.append(auth_log)
    parent = auth_log.parent
    base = auth_log.name
    for i in range(1, 32):
        for suffix in ("", ".gz"):
            candidate = parent / f"{base}.{i}{suffix}"
            if candidate.exists():
                files.append(candidate)
                break
    return files


def _read_log_lines(path: Path) -> Iterator[str]:
    """ファイルを行単位で yield する。.gz は自動解凍。"""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", errors="ignore") as f:
            yield from f
    else:
        with path.open("r", errors="ignore") as f:
            yield from f


def _parse_syslog_ts(
    month: str, day: str, time_str: str, now: datetime
) -> datetime | None:
    """syslog 形式 'May 17 23:45:00' を datetime に変換する。

    年は now を基準に推定。結果が 1 日以上未来になる場合は前年と判定
    (年跨ぎログを正しく扱うため)。
    """
    try:
        ts = datetime.strptime(
            f"{now.year} {month} {day} {time_str}",
            "%Y %b %d %H:%M:%S",
        )
    except ValueError:
        return None
    if ts > now + timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def _compute_ssh_failures(
    hours: int,
    auth_log: Path = AUTH_LOG,
    now: datetime | None = None,
) -> dict:
    """auth.log + ローテートから過去 N 時間の Failed password を集計する純関数。

    Args:
        hours: 何時間前までを対象にするか。
        auth_log: 主 auth.log の path。
        now: 時刻基準。None なら datetime.now()。テストで固定値を渡せる。
    """
    if now is None:
        now = datetime.now()

    files = _list_auth_log_files(auth_log)
    logger.info(
        "compute start: hours=%d files=%d (main=%s)",
        hours, len(files), auth_log,
    )

    if not files:
        logger.warning("auth.log not found: %s (no rotations either)", auth_log)
        return {
            "error": f"auth.log が見つかりません: {auth_log}",
            "hours": hours,
        }

    cutoff = now - timedelta(hours=hours)
    failure_count = 0
    parse_errors = 0
    subnet_counts: dict[str, int] = {}

    for log_file in files:
        for line in _read_log_lines(log_file):
            m = _FAILED_PASSWORD_RE.search(line)
            if not m:
                continue
            ts = _parse_syslog_ts(m["month"], m["day"], m["time"], now)
            if ts is None:
                parse_errors += 1
                continue
            if ts < cutoff:
                continue
            failure_count += 1
            masked = _mask_ipv4_to_slash24(m["ip"])
            subnet_counts[masked] = subnet_counts.get(masked, 0) + 1

    top = sorted(subnet_counts.items(), key=lambda kv: -kv[1])[:5]

    result = {
        "hours": hours,
        "total_failures": failure_count,
        "unique_source_subnets": len(subnet_counts),
        "top_source_subnets": [{"subnet": s, "count": c} for s, c in top],
        "parse_errors": parse_errors,
        "files_read": len(files),
    }
    logger.info(
        "compute done: total=%d subnets=%d parse_errors=%d files=%d",
        failure_count, len(subnet_counts), parse_errors, len(files),
    )
    return result


@mcp.tool
def get_ssh_failures(hours: int = 24) -> dict:
    """過去 N 時間の SSH ログイン失敗を集計して返す。

    auth.log 本体と logrotate 済みファイル (auth.log.1, auth.log.2.gz, ...) を
    横断して読み、cutoff 時刻でフィルタする。発信元 IP は CLAUDE.md 規約に従い
    /24 にマスク済み。

    Args:
        hours: 何時間前までを対象にするか (デフォルト 24)。

    Returns:
        集計サマリー dict (hours, total_failures, unique_source_subnets,
        top_source_subnets, parse_errors, files_read)。
    """
    return _compute_ssh_failures(hours)


# --- get_system_status -------------------------------------------------


DEFAULT_SERVICES: tuple[str, ...] = (
    "ssh",
    "ufw",
    "fail2ban",
    "systemd-timesyncd",
)
_GB = 1024 ** 3


def _systemctl_is_active(service: str, timeout: float = 5.0) -> str:
    """systemctl is-active <service> の出力を返す。

    systemctl 不在・タイムアウト・OS エラーは 'unknown' にフォールバック。
    sudo は不要 (is-active は read-only な status クエリ)。
    """
    if shutil.which("systemctl") is None:
        return "unknown"
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return "unknown"
    return result.stdout.strip() or "unknown"


def _compute_system_status(
    services: tuple[str, ...] | list[str] = DEFAULT_SERVICES,
) -> dict:
    """CPU / load / memory / disk / 主要サービスの稼働状態を集めて返す純関数。

    hostname / IP / ユーザー情報は返さない (CLAUDE.md「実 IP/ホスト名」保護方針)。
    cpu_percent は 0.5 秒サンプリング。それ以外は瞬時値。
    """
    logger.info("system_status start: services=%s", list(services))

    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_usage("/")
    load1, load5, load15 = psutil.getloadavg()
    uptime_sec = int(time.time() - psutil.boot_time())

    result = {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "load_average": {
            "1m": round(load1, 2),
            "5m": round(load5, 2),
            "15m": round(load15, 2),
        },
        "memory": {
            "total_gb": round(mem.total / _GB, 2),
            "used_gb": round(mem.used / _GB, 2),
            "available_gb": round(mem.available / _GB, 2),
            "percent": mem.percent,
        },
        "swap": {
            "total_gb": round(swap.total / _GB, 2),
            "used_gb": round(swap.used / _GB, 2),
            "percent": swap.percent,
        },
        "disk_root": {
            "total_gb": round(disk.total / _GB, 2),
            "used_gb": round(disk.used / _GB, 2),
            "free_gb": round(disk.free / _GB, 2),
            "percent": disk.percent,
        },
        "uptime_seconds": uptime_sec,
        "services": {s: _systemctl_is_active(s) for s in services},
    }
    logger.info(
        "system_status done: cpu=%s%% mem=%s%% disk=%s%% uptime=%ss services=%s",
        result["cpu_percent"], result["memory"]["percent"],
        result["disk_root"]["percent"], uptime_sec, result["services"],
    )
    return result


@mcp.tool
def get_system_status(services: list[str] | None = None) -> dict:
    """システムの現在状態 (read-only) を返す。

    Args:
        services: 状態を確認する systemd ユニット名のリスト。
                  None なら ['ssh', 'ufw', 'fail2ban', 'systemd-timesyncd']。

    Returns:
        CPU / load / memory / swap / disk(/) / uptime / services の dict。
    """
    return _compute_system_status(services or DEFAULT_SERVICES)


# --- get_pending_updates -----------------------------------------------


APT_CACHE_PATH = Path("/var/cache/apt/pkgcache.bin")

_KERNEL_NON_KERNEL_PACKAGES = frozenset({
    # `linux-*` を名前に含むが、カーネルそのものではないパッケージ
    "linux-libc-dev",  # ユーザ空間用 libc kernel headers
})


def _is_kernel_package(name: str) -> bool:
    """`linux-*` 系のパッケージを kernel 関連と見なす (一部の非 kernel を除外)。

    対象例: linux-image-*, linux-modules-*, linux-headers-*, linux-generic,
    linux-generic-hwe-24.04, linux-aws-*, linux-azure-* など。
    """
    if not name.startswith("linux-"):
        return False
    return name not in _KERNEL_NON_KERNEL_PACKAGES


def _apt_cache_age_seconds(cache_path: Path = APT_CACHE_PATH) -> int | None:
    """apt cache ファイルの mtime からの経過秒。ファイル不在なら None。"""
    if not cache_path.exists():
        return None
    return int(time.time() - cache_path.stat().st_mtime)


def _parse_apt_upgradable_line(line: str) -> dict | None:
    """`apt list --upgradable` の 1 行をパースする。

    フォーマット例 (apt は CLI 不安定を警告するが事実上の出力):
        gcc-13/noble-updates 13.3.0-6ubuntu2~24.04.1 amd64 [upgradable from: 13.2.0-23ubuntu4]
        libssl3t64/noble-security 3.0.13-0ubuntu3.5 amd64 [upgradable from: 3.0.13-0ubuntu3.4]

    マッチしない行 (header, blank 等) は None を返す。
    """
    if "/" not in line or "[upgradable from:" not in line:
        return None
    parts = line.split()
    if len(parts) < 4:
        return None
    name_source = parts[0]
    new_version = parts[1]
    arch = parts[2]
    if "/" not in name_source:
        return None
    name, source = name_source.split("/", 1)
    # "[upgradable from: <old>]" から old_version を取り出す
    old_version: str | None = None
    for i, tok in enumerate(parts):
        if tok == "from:" and i + 1 < len(parts):
            old_version = parts[i + 1].rstrip("]")
            break
    return {
        "name": name,
        "source": source,
        "new_version": new_version,
        "arch": arch,
        "old_version": old_version,
        "is_security": "-security" in source,
        "is_kernel": _is_kernel_package(name),
    }


def _list_upgradable_packages(
    timeout: float = 30.0,
) -> tuple[list[dict], str | None]:
    """`apt list --upgradable` を実行してパース結果を返す。

    Returns:
        (packages, error_or_None)
    """
    if shutil.which("apt") is None:
        return [], "apt command not found"
    try:
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return [], f"apt failed: {type(exc).__name__}"
    pkgs: list[dict] = []
    for line in result.stdout.splitlines():
        parsed = _parse_apt_upgradable_line(line)
        if parsed is not None:
            pkgs.append(parsed)
    return pkgs, None


def _compute_pending_updates(
    cache_path: Path = APT_CACHE_PATH,
    sample_size: int = 20,
) -> dict:
    """更新可能パッケージを集計して dict で返す純関数。"""
    logger.info("pending_updates start")
    pkgs, error = _list_upgradable_packages()
    if error:
        logger.warning("pending_updates: apt error: %s", error)
        return {"error": error, "total": 0, "cache_age_seconds": _apt_cache_age_seconds(cache_path)}

    security = [p for p in pkgs if p["is_security"]]
    kernel = [p for p in pkgs if p["is_kernel"]]
    result = {
        "cache_age_seconds": _apt_cache_age_seconds(cache_path),
        "total": len(pkgs),
        "security_count": len(security),
        "kernel_count": len(kernel),
        "kernel_update_needed": len(kernel) > 0,
        "security_packages": [p["name"] for p in security[:sample_size]],
        "kernel_packages": [p["name"] for p in kernel[:sample_size]],
        "all_packages_sample": [p["name"] for p in pkgs[:sample_size]],
    }
    logger.info(
        "pending_updates done: total=%d security=%d kernel=%d cache_age=%ss",
        result["total"], result["security_count"], result["kernel_count"],
        result["cache_age_seconds"],
    )
    return result


@mcp.tool
def get_pending_updates() -> dict:
    """apt の更新可能パッケージサマリを返す (read-only)。

    `apt list --upgradable` の出力を集計し、security update 数・kernel update
    の有無・パッケージ名サンプルを返す。sudo は不要 (cache の読み取りのみ)。
    cache が古い (`cache_age_seconds` 大) 場合は最新更新の取りこぼし可能性あり。

    Returns:
        total / security_count / kernel_update_needed / 各カテゴリの package サンプル等。
    """
    return _compute_pending_updates()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    mcp.run()
