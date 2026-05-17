"""homelab-watch MCP サーバー (Week 1 最小版)。

過去 N 時間の SSH ログイン失敗を集計する read-only ツールを提供する。
CLAUDE.md 規約に従い、発信元 IP は /24 にマスキングした上で返す。
"""
from __future__ import annotations

import logging
import os
import re
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


def _compute_ssh_failures(hours: int, auth_log: Path = AUTH_LOG) -> dict:
    """auth.log から過去 N 時間の Failed password を集計する純関数。

    MCP デコレータと分離してテスト容易性を確保する。
    """
    logger.info("compute start: hours=%d auth_log=%s", hours, auth_log)

    if not auth_log.exists():
        logger.warning("auth.log not found: %s", auth_log)
        return {
            "error": f"auth.log が見つかりません: {auth_log}",
            "hours": hours,
        }

    cutoff = datetime.now() - timedelta(hours=hours)
    failure_count = 0
    parse_errors = 0
    subnet_counts: dict[str, int] = {}

    for line in auth_log.read_text(errors="ignore").splitlines():
        m = _FAILED_PASSWORD_RE.search(line)
        if not m:
            continue
        try:
            ts = datetime.strptime(
                f"{datetime.now().year} {m['month']} {m['day']} {m['time']}",
                "%Y %b %d %H:%M:%S",
            )
        except ValueError:
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
    }
    logger.info(
        "compute done: total=%d subnets=%d parse_errors=%d",
        failure_count, len(subnet_counts), parse_errors,
    )
    return result


@mcp.tool
def get_ssh_failures(hours: int = 24) -> dict:
    """過去 N 時間の SSH ログイン失敗を集計して返す。

    発信元 IP は /24 にマスク済みで、LLM 前段で個別ホスト特定を不可能にする。

    Args:
        hours: 何時間前までを対象にするか (デフォルト 24)。

    Returns:
        集計サマリー dict。
    """
    return _compute_ssh_failures(hours)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    mcp.run()
