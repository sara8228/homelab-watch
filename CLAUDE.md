# homelab-watch プロジェクト規約

## プロジェクトの目的
自宅 Ubuntu Server (検証 VM) の運用・セキュリティ状況を集約し、
Claude Code + MCP サーバー経由で自然言語監視・分析できる仕組みを構築する。
CISSP / 情報処理安全確保支援士の知見を hands-on で深める学習目的を兼ねる。

## データ分類と取扱方針
| 分類 | 例 | コミット可否 | 加工 |
|---|---|---|---|
| Public | コード, README, ライセンス, 一般的な設計メモ | OK | - |
| Internal | プロジェクト構成, サンプル設定, 集約後の統計 | Private repo に限り OK | - |
| Confidential | LAN IP / ホスト名 / 実 auth.log 抜粋 / SQLite データ / 認証情報 | NG | secrets は環境変数 or .env (gitignore)、ログは集計・匿名化必須 |

実 IP/ホスト名はコードコメント・コミットメッセージ・ドキュメントにも書かない。
将来 Public 化する可能性を残すため。

## セキュリティ原則
- **bind は LAN 内のみ**: 127.0.0.1 または LAN IP に bind。0.0.0.0 への bind は禁止
- **root 不使用**: MCP サーバー・ダッシュボードは ub-admin (将来は専用 service user 検討) で実行。サーバープロセスから sudo を呼ばない
- **MCP ツールは read-only から開始**: ファイルアクセスは明示ホワイトリスト (例: `/var/log/auth.log`, `journalctl` 読み取り)。書き込み・状態変更系は個別議論
- **任意コード実行ツール禁止**: `subprocess.run(user_input)` 相当のツールは作らない
- **secrets は環境変数 / .env**: コードに直書きしない。`.env` は gitignore 必須
- **Python は venv 必須**: グローバル pip install は禁止
- **依存パッケージは最小限**: PyPI 公式 + 著名作者 + 直近メンテのもの優先。脆弱性は `pip-audit` で定期スキャン (`make audit`)

## AI エージェントへ渡すデータの加工
- IP アドレス: マスキング (例: `192.168.1.X` → `192.168.1.0/24` に丸める)
- ユーザー名: 既知 internal を除きハッシュ or 番号化
- 生ログを丸投げしない (件数集計・トップ N など、加工後の形で渡す)
- プロンプトインジェクション対策: ログ文字列をそのまま LLM に渡さず、構造化 dict で返す

## 技術スタック
- Python 3.11+ (現状 3.12.3)
- MCP サーバー: FastMCP (stdio 通信。Week 3+ で network bind を検討する場合は別途設計)
- Web ダッシュボード: FastAPI + Jinja2 (Week 2 以降)
- DB: SQLite

## コーディング規約
- 型ヒント必須 (Python 3.11+ 構文 OK)
- docstring は日本語可
- ログは標準 logging モジュール、レベル INFO 既定
- ファイル/関数名は英語、コメントは日本語可
- 例外は握りつぶさない。stack trace は残し secrets は伏せる
- ファイルパスは pathlib.Path で扱う

## Git / PR 運用
- `main` への直 push 禁止、feature ブランチ → PR → squash merge
- 各 PR の説明欄に「機密情報なし」を明記
- コミットメッセージは日本語/英語どちらでも可、命令形
- secrets を誤コミットしたら即 revoke + history 削除 (BFG / git filter-repo)

## 禁止事項
- 取得したログを Anthropic に直接送らない (上記「データ加工」を通す)
- パスワードや鍵の生データを扱うコードは書かない
- 外部公開 (Public repo 化, 外部 API 公開) を伴う変更は事前に確認を求める
- 検証 VM 用の一時 NOPASSWD sudoers (`/etc/sudoers.d/99-claude-temp`) は Week 1 完了時に削除

## 改訂履歴
- v0.1 (Week 1): 初版
