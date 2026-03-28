# MCP Server with Google OAuth — 実装プラン

## 概要

Google OAuthで保護されたMCPサーバーをGoで実装する。
Claude Codeクライアントから `claude mcp add --transport http` で接続できることをゴールとする。

---

## ディレクトリ構成

```
mcp-google-oauth/
├── go.mod
├── go.sum
├── main.go
├── auth/
│   ├── metadata.go     # /.well-known エンドポイント群
│   ├── middleware.go   # Bearer JWT検証ミドルウェア
│   └── oauth.go        # /authorize /callback /token ハンドラ
└── README.md
```

---

## go.mod

```
module mcp-google-oauth

go 1.22

require (
    github.com/modelcontextprotocol/go-sdk v1.4.0
    github.com/MicahParks/keyfunc/v3 v3.3.5
    github.com/golang-jwt/jwt/v5 v5.2.1
)
```

---

## 環境変数（direnvで設定済み）

| 変数名 | 内容 |
|---|---|
| `GOOGLE_CLIENT_ID` | Google Cloud ConsoleのOAuth Client ID |
| `GOOGLE_CLIENT_SECRET` | 同Client Secret |
| `RESOURCE_URL` | このサーバー自身のURL（例: `http://localhost:8080`） |

---

## 実装するファイルと責務

### `auth/metadata.go`

以下の2エンドポイントを実装する。

**`GET /.well-known/oauth-protected-resource`**

RFC 9728準拠。Claude Codeが最初に叩くエンドポイント。
以下のJSONを返す：

```json
{
  "resource": "{RESOURCE_URL}",
  "authorization_servers": ["{RESOURCE_URL}"],
  "scopes_supported": ["openid", "email", "profile"]
}
```

注意: `authorization_servers` にはGoogleではなくこのサーバー自身のURLを入れる。
Claude Codeはここに書かれたURLに対して次のメタデータ取得を行う。

**`GET /.well-known/oauth-authorization-server`**

RFC 8414準拠。Claude Codeが認可エンドポイント等を発見するために使う。
以下のJSONを返す（DCR endpointは含めない。GoogleはDCR非対応のため）：

```json
{
  "issuer": "{RESOURCE_URL}",
  "authorization_endpoint": "{RESOURCE_URL}/authorize",
  "token_endpoint": "{RESOURCE_URL}/token",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code"],
  "code_challenge_methods_supported": ["S256"]
}
```

---

### `auth/oauth.go`

以下の3エンドポイントを実装する。

**`GET /authorize`**

Claude Codeから受け取ったパラメータをそのままGoogleの認可URLに引き継いでリダイレクトする。
引き継ぐパラメータ: `code_challenge`, `code_challenge_method`, `state`, `redirect_uri`

Googleへのリダイレクト先:
```
https://accounts.google.com/o/oauth2/v2/auth?
  client_id={GOOGLE_CLIENT_ID}
  &redirect_uri={RESOURCE_URL}/callback
  &response_type=code
  &scope=openid email profile
  &code_challenge={code_challenge}
  &code_challenge_method=S256
  &state={state}
  &access_type=offline
```

**`GET /callback`**

Googleからのリダイレクトでcodeとstateを受け取る。
受け取ったcodeとstateをそのままClaude Codeの `redirect_uri` にリダイレクトして返す。

Claude CodeのredirectURIは `/authorize` リクエストの `redirect_uri` パラメータに含まれている。
セッション（インメモリmap、キー: state値）に `redirect_uri` を一時保存して `/callback` で取り出す。

**`POST /token`**

Claude CodeからのPKCEトークン交換リクエストを受け取り、Googleのトークンエンドポイントへプロキシする。

受け取るパラメータ: `grant_type`, `code`, `redirect_uri`, `code_verifier`, `client_id`
Googleへ送るパラメータ: 上記 + `client_secret`（環境変数から追加）

GoogleのレスポンスをそのままClaude Codeに返す。

---

### `auth/middleware.go`

**`func NewMiddleware(resourceURL, clientID string) (*Middleware, error)`**

起動時にGoogleのJWKSエンドポイント（`https://www.googleapis.com/oauth2/v3/certs`）から
公開鍵を取得・キャッシュする。`keyfunc` ライブラリを使う。

**`func (m *Middleware) Wrap(next http.Handler) http.Handler`**

以下のパスは認証スキップ:
- `/.well-known/` 以下すべて
- `/authorize`
- `/callback`
- `/token`

それ以外のリクエストに対して:
1. `Authorization: Bearer {token}` ヘッダを確認
2. なければ401 + `WWW-Authenticate: Bearer resource_metadata="{RESOURCE_URL}/.well-known/oauth-protected-resource"` を返す
3. JWTを検証（署名・iss・exp）
4. `aud` クレームに `GOOGLE_CLIENT_ID` が含まれるか確認
5. 問題なければ `next` に処理を渡す

Googleが発行する `id_token` を Bearer tokenとして使う前提で実装する。
（GoogleのAccessTokenはJWTではないため、`id_token` を使う）

---

### `main.go`

**起動処理:**

1. 環境変数 `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `RESOURCE_URL` を読み込む。いずれかが空なら `log.Fatal` で終了。
2. `auth.NewMiddleware` でJWT検証ミドルウェアを初期化
3. MCPサーバーを作成し、以下のツールを登録:
   - `whoami`: 引数なし、認証中のメールアドレスを返すためのツール
4. `mcp.NewStreamableHTTPHandler` でMCPのHTTPハンドラを作成
5. `http.NewServeMux` でルーティング設定:
   - `/.well-known/oauth-protected-resource` → `auth.ProtectedResourceMetadataHandler`
   - `/.well-known/oauth-authorization-server` → `auth.AuthorizationServerMetadataHandler`
   - `/authorize` → `auth.AuthorizeHandler`
   - `/callback` → `auth.CallbackHandler`
   - `/token` → `auth.TokenHandler`
   - `/` → `middleware.Wrap(mcpHandler)`
6. `:8080` でListenAndServe

---

## 動作確認手順

実装完了後、以下の順で確認する。

```bash
# 1. サーバー起動
go run .

# 2. well-knownが返るか確認
curl http://localhost:8080/.well-known/oauth-protected-resource | jq
curl http://localhost:8080/.well-known/oauth-authorization-server | jq

# 3. 未認証でMCPにアクセスすると401が返るか確認
curl -v http://localhost:8080/

# 4. Claude Codeから接続
claude mcp add --transport http \
  --callback-port 54321 \
  my-google-mcp \
  http://localhost:8080

# 5. ブラウザが開いてGoogleログイン画面が出ることを確認

# 6. 接続後、ツールを呼び出す
# Claude Code内で: "whoamiツールを呼び出して"
```

---

## 実装上の注意点

- セッション保存はインメモリ `map[string]string`（キー: state, 値: redirect_uri）で十分。練習用途のため永続化不要。
- stateの衝突を避けるため `sync.Mutex` でmapへのアクセスを保護すること。
- Googleが返す `id_token` はJWTだが、`access_token` はJWTではない。Bearerとして検証できるのは `id_token` のみ。
- `/token` プロキシ時、Googleからのレスポンスに含まれる `id_token` をClaude CodeがそのままBearer tokenとして使う想定。
- Content-Typeは各エンドポイントで `application/json` を明示すること。
- エラーハンドリングは `log.Printf` + 適切なHTTPステータスコードで十分。
