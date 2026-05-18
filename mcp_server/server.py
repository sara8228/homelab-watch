"""homelab-watch MCP サーバー (Week 2 拡張版)。

過去 N 時間の SSH ログイン失敗を集計する read-only ツールを提供する。
- /var/log/auth.log とローテートファイル (auth.log.1, auth.log.2.gz, ...) を横断して読む
- 年跨ぎ timestamp は now を基準に前年判定 (clock skew 1 日許容)
- 発信元 IP は CLAUDE.md 規約に従い /24 にマスキング
"""
from __future__ import annotations

import gzip
import logging
import os
import re
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path

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


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    mcp.run()
