package main

import (
	"context"
	"log"
	"net/http"
	"os"

	mcpauth "mcp-google-oauth/auth"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	resourceURL := os.Getenv("RESOURCE_URL")

	if clientID == "" || clientSecret == "" || resourceURL == "" {
		log.Fatal("GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, RESOURCE_URL must be set")
	}

	middleware, err := mcpauth.NewMiddleware(resourceURL, clientID)
	if err != nil {
		log.Fatalf("failed to init middleware: %v", err)
	}

	// MCPサーバー作成
	server := mcp.NewServer(&mcp.Implementation{Name: "mcp-google-oauth", Version: "1.0.0"}, nil)

	// whoamiツールを登録
	type NoInput struct{}
	type WhoamiOutput struct {
		Email string `json:"email"`
	}
	mcp.AddTool(server, &mcp.Tool{
		Name:        "whoami",
		Description: "認証中のユーザーのメールアドレスを返す",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ NoInput) (*mcp.CallToolResult, WhoamiOutput, error) {
		email := mcpauth.EmailFromContext(ctx)
		if email == "" {
			email = "(email not found in token)"
		}
		return nil, WhoamiOutput{Email: email}, nil
	})

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, nil)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", mcpauth.ProtectedResourceMetadataHandler)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", mcpauth.AuthorizationServerMetadataHandler)
	mux.HandleFunc("GET /authorize", mcpauth.AuthorizeHandler)
	mux.HandleFunc("GET /callback", mcpauth.CallbackHandler)
	mux.HandleFunc("POST /token", mcpauth.TokenHandler)
	mux.HandleFunc("POST /register", mcpauth.RegisterHandler)
	mux.Handle("/", middleware.Wrap(mcpHandler))

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
