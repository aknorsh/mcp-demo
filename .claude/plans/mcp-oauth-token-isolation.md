# Plan: OAuth Token Isolation（Googleトークンの完全隠蔽）

## 目的

現行のデモ実装では、`/token` レスポンスに Google の `access_token` / `id_token` / `refresh_token` が
Client に漏洩している。本 Plan では Client との境界を明確にし、以下の状態を達成する。

- Client が受け取るのは **独自 code(B)** と **独自 access_token（JWT）** のみ
- Google トークン類はサーバー内部に秘匿保持
- mcpauth サーバーが Google の存在を完全に隠蔽する

---

## 変更対象ファイル

`mcp-google-oauth/auth/` 配下のみを変更する。

---

## Step 1: 内部ストアの追加

### 追加する型・変数

```go
// code(B) -> userID のマッピング（/callback で書き込み、/token で消費）
var (
    codeMu    sync.Mutex
    codeStore = map[string]string{} // codeB -> userID
)

// userID -> Google tokens のマッピング（/callback で書き込み、middleware で参照）
var (
    tokenMu    sync.Mutex
    tokenStore = map[string]GoogleTokens{}
)

type GoogleTokens struct {
    AccessToken  string
    RefreshToken string
    IDToken      string
}
```

---

## Step 2: CallbackHandler の変更

### 現行の動作
1. Google から code(A) を受け取る
2. code(A) をそのまま Client へ返す（トークン交換しない）

### 変更後の動作
1. Google から code(A) を受け取る
2. **その場で** Google `/token` エンドポイントへ code(A) を送りトークン交換
3. Google トークンを `tokenStore[userID]` に保存（外に出さない）
4. 独自の code(B) を生成し `codeStore[codeB] = userID` に保存
5. Client へは code(B) のみ返す

### 実装イメージ

```go
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
    codeA := q.Get("code")
    state := q.Get("state")

    // セッションから redirect_uri を取得（現行と同じ）
    sessionMu.Lock()
    redirectURI, ok := sessions[state]
    delete(sessions, state)
    sessionMu.Unlock()

    // ① Google とのトークン交換をここで行う
    googleTokens, err := exchangeWithGoogle(codeA)
    if err != nil {
        http.Error(w, "token exchange failed", http.StatusBadGateway)
        return
    }

    // ② userID を id_token（JWT）から取得
    userID, err := extractSub(googleTokens.IDToken)
    if err != nil {
        http.Error(w, "invalid id_token", http.StatusInternalServerError)
        return
    }

    // ③ Google トークンを内部保存（外には出さない）
    tokenMu.Lock()
    tokenStore[userID] = googleTokens
    tokenMu.Unlock()

    // ④ 独自 code(B) を発行
    codeB := generateRandom(32)
    codeMu.Lock()
    codeStore[codeB] = userID
    codeMu.Unlock()

    // ⑤ Client へは code(B) のみ返す
    target, _ := url.Parse(redirectURI)
    params := target.Query()
    params.Set("code", codeB)
    params.Set("state", state)
    target.RawQuery = params.Encode()
    http.Redirect(w, r, target.String(), http.StatusFound)
}
```

---

## Step 3: TokenHandler の変更

### 現行の動作
1. Client から code(A) を受け取る
2. Google `/token` へそのままプロキシ
3. Google レスポンスを（access_token を id_token で上書きしつつ）そのまま返す
   → `access_token`, `refresh_token`, `id_token` が Client に漏洩

### 変更後の動作
1. Client から code(B) を受け取る
2. `codeStore` から userID を取得（code(B) を消費）
3. 独自 JWT を発行（claims: sub=userID, exp=1h）
4. Client へは独自 JWT のみ返す（Google トークンは一切含めない）

### 実装イメージ

```go
func TokenHandler(w http.ResponseWriter, r *http.Request) {
    codeB := r.FormValue("code")

    // ① code(B) → userID（使い捨て）
    codeMu.Lock()
    userID, ok := codeStore[codeB]
    delete(codeStore, codeB)
    codeMu.Unlock()

    if !ok {
        http.Error(w, "invalid code", http.StatusBadRequest)
        return
    }

    // ② 独自 JWT を発行（Google とは無関係な署名鍵）
    myJWT, err := issueJWT(userID)
    if err != nil {
        http.Error(w, "token issue failed", http.StatusInternalServerError)
        return
    }

    // ③ Client へは独自 JWT のみ返す
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]any{
        "access_token": myJWT,
        "token_type":   "Bearer",
        "expires_in":   3600,
        // refresh_token, id_token は意図的に含めない
    })
}
```

---

## Step 4: middleware の変更

### 現行の動作
- Bearer トークン（Google id_token）を Google 公開鍵で検証
- userID（sub）を取得して context に詰める

### 変更後の動作
- Bearer トークン（独自 JWT）を **自前の秘密鍵** で検証
- userID を取得し `tokenStore[userID]` から Google tokens を取得
- Google tokens を context に詰めて whoami handler へ渡す

---

## Step 5: 追加するヘルパー関数

| 関数 | 役割 |
|---|---|
| `exchangeWithGoogle(codeA string) (GoogleTokens, error)` | Google `/token` を叩いてトークン取得 |
| `extractSub(idToken string) (string, error)` | JWT の sub クレームを取り出す（署名検証込み） |
| `generateRandom(n int) string` | crypto/rand で安全なランダム文字列を生成 |
| `issueJWT(userID string) (string, error)` | 自前秘密鍵で JWT を署名・発行 |
| `verifyJWT(token string) (Claims, error)` | 自前秘密鍵で JWT を検証 |

JWT の署名には `github.com/golang-jwt/jwt/v5` を使うのが最も手軽。

---

## 変更しないもの

- `AuthorizeHandler` … PKCE の転送ロジックは変更不要
- `RegisterHandler` … Google が DCR 非対応である制約は変わらないため現状維持
- `/.well-known` 系ハンドラ … 変更不要
- MCP ツール（whoami）の実装 … context から userID / Google tokens を取得する
  インターフェースが変わるだけで、ロジック自体は変更不要

---

## 完了条件

- [ ] `/token` レスポンスに `id_token`, `refresh_token`, Google `access_token` が含まれないこと
- [ ] Client が受け取る `access_token` が自前署名の JWT であること
- [ ] `middleware` が自前秘密鍵で JWT を検証できること
- [ ] whoami ツールが引き続き Google UserInfo を返せること
- [ ] サーバー再起動後に既存トークンが無効になること（インメモリ制約として明示的に許容）
