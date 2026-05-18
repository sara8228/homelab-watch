# homelab-watch

自宅 Ubuntu Server (検証 VM) の運用・セキュリティ状況を Claude Code + MCP 経由で
自然言語監視・分析するプロジェクト。CISSP / 情報処理安全確保支援士の知見を
hands-on で深める学習目的を兼ねる。

## 現状 (Week 2 完了)

- ✅ Ubuntu 24.04 LTS 上で動作 (ufw + fail2ban + unattended-upgrades 構成)
- ✅ Claude Code (v2.1+) + OAuth 認証
- ✅ FastMCP ベースの MCP サーバー (`mcp_server/server.py`)
- ✅ MCP read-only ツール 3 つ:
  - `get_ssh_failures(hours)`: auth.log + ローテート (`.1` / `.2.gz` 等) を横断して SSH 失敗を集計。発信元 IP は `/24` マスク、年跨ぎ timestamp 対応
  - `get_system_status(services)`: psutil で CPU / load / mem / swap / disk(/) / uptime + 指定サービスの稼働状態 (default: ssh, ufw, fail2ban, systemd-timesyncd)
  - `get_pending_updates()`: `apt list --upgradable` をパースして total / security_count / kernel_update_needed を返す。cache 鮮度 (`cache_age_seconds`) も併記
- ✅ pytest による単体テスト **19 ケース** (Week 1: 4 / Week 2: 15)
- ✅ `make test` / `make audit` (pip-audit ベース脆弱性スキャン、現状 0 件)
- ✅ プロジェクトスコープ `.mcp.json` で Claude Code から自動ロード

## アーキテクチャ

```
[Mac]                            [Ubuntu Lab VM]
  │                                  │
  │  SSH (key auth, LAN only)        ├─ Claude Code (tmux 内, OAuth)
  ├─────────────────────────────────▶│   │
                                     │   ▼ stdio
                                     ├─ MCP サーバー (FastMCP)
                                     │   ├─ get_ssh_failures(hours)
                                     │   ├─ get_system_status(services)
                                     │   └─ get_pending_updates()
                                     │
                                     ├─ /var/log/auth.log{,.1,.2.gz,...}  (adm グループ read)
                                     ├─ /proc, /sys                       (psutil 経由)
                                     ├─ systemctl is-active <unit>        (read-only クエリ)
                                     └─ /var/cache/apt/pkgcache.bin       (apt list --upgradable)
```

Week 3 以降: FastAPI ダッシュボード (LAN bind + Basic 認証), SQLite 蓄積, 異常検知 を予定。

## セットアップ (新規 clone から)

```bash
# 1. clone (SSH 鍵設定済みの GitHub アカウント前提)
git clone git@github.com:sara8228/homelab-watch.git
cd homelab-watch

# 2. Python venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install "mcp[cli]" fastmcp psutil pytest pip-audit

# 3. テスト
make test

# 4. 依存脆弱性スキャン
make audit

# 5. Claude Code 起動 (.mcp.json が自動検出される)
claude
```

初回 `claude` 起動時に `homelab-watch` MCP サーバーの承認プロンプトが出るので
**`Use this MCP server`** を選択 (将来追加される MCP サーバーも個別レビューしたい方針のため、
"Use this and all future MCP servers" は推奨しない)。

## 使い方 (自然言語プロンプト例)

Claude Code のプロンプトに日本語で質問:

```
過去 24 時間の SSH ログイン失敗を教えて。発信元サブネットの上位もあれば見たい。
```
→ `get_ssh_failures(24)` が呼ばれ、`/24` マスク済みサブネット集計を返答。

```
このサーバーの今の状態を要約して。CPU・メモリ・ディスク・主要サービスの稼働状況。
```
→ `get_system_status()` が呼ばれ、cpu_percent / load_average / memory / disk_root / services を返答。

```
未適用のパッケージ更新ある? security update や kernel update があれば優先度高めに教えて。
```
→ `get_pending_updates()` が呼ばれ、`security_count` と `kernel_update_needed` を強調した要約。

## ディレクトリ構成

```
homelab-watch/
├── CLAUDE.md                       プロジェクト規約 (Claude Code が自動 load)
├── README.md                       このファイル
├── pyproject.toml                  pytest 設定
├── Makefile                        test / audit / help ターゲット
├── .mcp.json                       Claude Code 向け MCP サーバー定義
├── .gitignore
├── mcp_server/
│   ├── __init__.py
│   └── server.py                   MCP サーバー本体 + 3 ツール
├── tests/
│   ├── test_get_ssh_failures.py
│   ├── test_get_system_status.py
│   └── test_get_pending_updates.py
├── dashboard/                      (Week 3+: FastAPI ダッシュボード, 現状 .gitkeep のみ)
├── data/                           (runtime SQLite, gitignored)
└── logs/                           (runtime ログ, gitignored)
```

## セキュリティ方針

詳細は [CLAUDE.md](./CLAUDE.md) を参照。主な原則:

- **LAN 内 bind のみ** (`0.0.0.0` への bind 禁止)
- **MCP ツールは read-only から開始**、書き込み系は個別議論
- **AI に渡すデータは事前加工** (IP は `/24` マスキング、hostname/IP は返さない、プロンプトインジェクション対策で構造化 dict を返す)
- **secrets は `.env` (gitignored) または環境変数**、コード直書き禁止
- **`auth.log` 等の Confidential データはコミットしない**
- **`main` への直 push 禁止**、PR + Branch Ruleset で強制
- **`pip-audit` で依存脆弱性を定期スキャン**

## 開発

```bash
# よく使うコマンド (Makefile 経由)
make test    # pytest を実行
make audit   # pip-audit で依存脆弱性スキャン
make help    # ターゲット一覧

# 個別コマンド
.venv/bin/pytest -v                            # テスト実行
.venv/bin/python mcp_server/server.py          # MCP サーバー単体起動 (stdio で待機)
HOMELAB_WATCH_AUTH_LOG=/path/to/fake.log \
  .venv/bin/python -c "from mcp_server.server import _compute_ssh_failures; print(_compute_ssh_failures(24))"
```

## ライセンス
(検証中。Week 4 で決定予定)
