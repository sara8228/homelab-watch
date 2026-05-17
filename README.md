# homelab-watch

自宅 Ubuntu Server (検証 VM) の運用・セキュリティ状況を Claude Code + MCP 経由で
自然言語監視・分析するプロジェクト。CISSP / 情報処理安全確保支援士の知見を
hands-on で深める学習目的を兼ねる。

## 現状 (Week 1 完了)

- ✅ Ubuntu 24.04 LTS 上で動作 (ufw + fail2ban + unattended-upgrades 構成)
- ✅ Claude Code (v2.1+) + OAuth 認証
- ✅ FastMCP ベースの MCP サーバー (`mcp_server/server.py`)
- ✅ 過去 N 時間の SSH ログイン失敗を集計する read-only ツール `get_ssh_failures`
  - 発信元 IP は `/24` にマスキングして返す (CLAUDE.md 規約準拠)
- ✅ pytest による単体テスト 4 ケース (24h 窓内集計 / 48h 拡張 / auth.log 不在 / マスキング境界)
- ✅ プロジェクトスコープ `.mcp.json` で Claude Code から自動ロード

## アーキテクチャ (Week 1)

```
[Mac]                            [Ubuntu Lab VM]
  │                                  │
  │  SSH (key auth, LAN only)        ├─ Claude Code (tmux 内, OAuth)
  ├─────────────────────────────────▶│   │
                                     │   ▼ stdio
                                     ├─ MCP サーバー (FastMCP)
                                     │   └─ get_ssh_failures(hours: int)
                                     │
                                     └─ /var/log/auth.log (adm グループで read-only)
```

Week 2 以降: `get_system_status`, `get_pending_updates`, FastAPI ダッシュボード, SQLite 蓄積, 異常検知 を予定。

## セットアップ (新規 clone から)

```bash
# 1. clone (SSH 鍵設定済みの GitHub アカウント前提)
git clone git@github.com:sara8228/homelab-watch.git
cd homelab-watch

# 2. Python venv
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install "mcp[cli]" fastmcp pytest

# 3. テスト
pytest

# 4. Claude Code 起動 (.mcp.json が自動検出される)
claude
```

初回 `claude` 起動時に `homelab-watch` MCP サーバーの承認プロンプトが出るので
**`Use this MCP server`** を選択 (将来追加される MCP サーバーも個別レビューしたい方針のため、
"Use this and all future MCP servers" は推奨しない)。

## 使い方

Claude Code のプロンプトで自然言語で質問:

> 過去 24 時間の SSH ログイン失敗を教えて。発信元サブネットの上位もあれば見たい。

Claude が `get_ssh_failures` ツールを呼び、結果を解釈して整形した表を返す。

## ディレクトリ構成

```
homelab-watch/
├── CLAUDE.md              プロジェクト規約 (Claude Code が自動 load)
├── README.md              このファイル
├── pyproject.toml         pytest 設定
├── .mcp.json              Claude Code 向け MCP サーバー定義
├── .gitignore
├── mcp_server/            MCP サーバー実装
│   ├── __init__.py
│   └── server.py
├── tests/                 pytest テスト
│   └── test_get_ssh_failures.py
├── dashboard/             (Week 2+: FastAPI ダッシュボード, 現状 .gitkeep のみ)
├── data/                  (runtime SQLite, gitignored)
└── logs/                  (runtime ログ, gitignored)
```

## セキュリティ方針

詳細は [CLAUDE.md](./CLAUDE.md) を参照。主な原則:

- **LAN 内 bind のみ** (`0.0.0.0` への bind 禁止)
- **MCP ツールは read-only から開始**、書き込み系は個別議論
- **AI に渡すデータは事前加工** (IP は `/24` マスキング、生ログは渡さない、プロンプトインジェクション対策で構造化 dict を返す)
- **secrets は `.env` (gitignored) または環境変数**、コード直書き禁止
- **`auth.log` 等の Confidential データはコミットしない**
- **`main` への直 push 禁止**、PR + Branch Ruleset で強制

## 開発

```bash
# テスト実行
pytest -v

# MCP サーバー単体起動 (stdio で待機。動作確認用)
.venv/bin/python mcp_server/server.py

# テスト用 auth.log で実行
HOMELAB_WATCH_AUTH_LOG=/path/to/fake.log python -c "from mcp_server.server import _compute_ssh_failures; print(_compute_ssh_failures(24))"
```

## ライセンス
(検証中。Week 4 で決定予定)
