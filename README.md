# mcp-google-oauth

Google OAuth で保護された MCP サーバーの実装例。
Claude Code から `claude mcp add --transport http` で接続できる。

## 構成

```
mcp-google-oauth/
├── go.mod
├── main.go
└── auth/
    ├── metadata.go   # /.well-known エンドポイント (RFC 9728 / RFC 8414)
    ├── oauth.go      # /authorize /callback /token /register ハンドラ
    └── middleware.go # Bearer JWT 検証ミドルウェア
```

## 認証フロー

```
Claude Code
  │
  ├─ GET /.well-known/oauth-protected-resource   (RFC 9728)
  ├─ GET /.well-known/oauth-authorization-server (RFC 8414)
  ├─ POST /register   ← DCR (RFC 7591) フェイク実装、Google Client ID を返す
  │
  ├─ GET /authorize   ← Google の認可 URL へリダイレクト
  │
  ├─ GET /callback    ← Google から code(A) を受け取り、トークン交換
  │       │             Google トークンをサーバー内部に保存
  │       └─ Client へは独自 code(B) のみ返す
  ├─ POST /token      ← code(B) を消費し、独自署名 JWT を発行
  │       └─ Google トークンは一切含まない
  │
  └─ POST /mcp        ← Bearer 独自 JWT で認証、MCP プロトコル
```

### Google トークンの隠蔽

Client（Claude Code）が受け取るのは **独自 JWT（HS256）** のみ。
Google の `access_token` / `refresh_token` / `id_token` はサーバー内部に秘匿保持され、外部に漏洩しない。

| 場所 | 保持するもの |
|---|---|
| Client | 独自 JWT（sub=Google userID, exp=1h）|
| サーバー（インメモリ）| Google tokens（userID をキーに保存）|

> **注意:** サーバーを再起動すると Google tokens・code ストアがリセットされ、既存の JWT は無効になる。

## 前提条件

- Go 1.22 以上
- Google Cloud Console で OAuth 2.0 クライアント ID を作成済み
  - 種類: **ウェブ アプリケーション**
  - 承認済みのリダイレクト URI に `http://localhost:8080/callback` を追加

## 環境変数

| 変数名 | 内容 |
|---|---|
| `GOOGLE_CLIENT_ID` | Google Cloud Console の OAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | 同 Client Secret |
| `RESOURCE_URL` | このサーバー自身の URL（例: `http://localhost:8080`）|

[direnv](https://direnv.net/) を使う場合は `.envrc` に記載する。

## セットアップ & 起動

```bash
# 依存解決
go mod tidy

# サーバー起動
go run .
```

## 動作確認

```bash
# メタデータが返るか確認
curl http://localhost:8080/.well-known/oauth-protected-resource | jq
curl http://localhost:8080/.well-known/oauth-authorization-server | jq

# 未認証で 401 が返るか確認
curl -v http://localhost:8080/

# Claude Code から接続
claude mcp add --transport http --callback-port 54321 my-google-mcp http://localhost:8080
```

接続後、ブラウザで Google ログイン画面が開く。

## 利用可能なツール

### `whoami`

認証中のユーザーのメールアドレスを返す。

```
> whoamiツールを呼び出して
{ "email": "you@example.com" }
```
