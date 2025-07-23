package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/syslog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Configuration loaded from environment variables
type Config struct {
	BindIP   string
	Port     string
	Hostname string
	TLSCert  string
	TLSKey   string
}

// Load configuration from environment variables with defaults
func loadConfig() Config {
	config := Config{
		BindIP:   getEnv("BIND_IP", "127.0.0.1"),
		Port:     getEnv("PORT", "8080"),
		Hostname: getEnv("OAUTH_HOSTNAME", "localhost"),
		TLSCert:  getEnv("TLS_CERT", ""),
		TLSKey:   getEnv("TLS_KEY", ""),
	}

	// If hostname is not set and we're binding to all interfaces, try to be smart
	if config.Hostname == "localhost" && config.BindIP == "0.0.0.0" {
		config.Hostname = "localhost"
	}

	return config
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Initialize syslog logger
func initLogger() {
	syslogWriter, err := syslog.New(syslog.LOG_INFO|syslog.LOG_DAEMON, "fake-oauth")
	if err != nil {
		// Fallback to stdout if syslog is not available
		log.Printf("Warning: Could not connect to syslog, using stdout: %v", err)
		logger = log.New(os.Stdout, "[fake-oauth] ", log.LstdFlags)
		return
	}
	logger = log.New(syslogWriter, "", 0) // syslog handles timestamps
	logger.Println("Logger initialized with syslog")
}

// Global config and logger
var (
	config Config
	logger *log.Logger
)

// In-memory storage for simplicity
var (
	authCodes    = make(map[string]AuthCodeData)
	accessTokens = make(map[string]UserData)
)

type UserData struct {
	Fields map[string]string
	Scopes []string
}

type AuthCodeData struct {
	RedirectURI string
	UserData    UserData
	ExpiresAt   time.Time
	Scopes      []string
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type UserInfoResponse map[string]string

const loginPageHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Dummy OAuth Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], input[type="email"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
        button:hover { background-color: #0056b3; }
        .header { text-align: center; margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="header">
        <h2>Dummy OAuth Login</h2>
        <p>Provide information for the requested scopes</p>
    </div>
    <form method="POST" action="/oauth/login">
        <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
        <input type="hidden" name="client_id" value="{{.ClientID}}">
        <input type="hidden" name="state" value="{{.State}}">
        <input type="hidden" name="scopes" value="{{.ScopesRaw}}">
        {{range .Scopes}}
            <div class="form-group">
                <label for="{{.}}">{{.}}</label>
                <input type="{{if eq . "email"}}email{{else}}text{{end}}" id="{{.}}" name="{{.}}" required placeholder="{{.}}">
            </div>
        {{end}}
        <button type="submit">Authorize</button>
    </form>
</body>
</html>
`

const indexPageHTML = `
<!DOCTYPE html>
<html>
<head>
    <title>Dummy OAuth Server</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 40px; }
        .endpoint { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; margin-bottom: 15px; }
        .endpoint h3 { margin-top: 0; color: #495057; }
        .url { font-family: monospace; font-size: 14px; background: #e9ecef; padding: 8px; border-radius: 3px; word-break: break-all; }
        .description { margin-top: 10px; color: #6c757d; font-size: 14px; }
        .example { background: #f1f3f4; padding: 10px; border-radius: 3px; font-family: monospace; font-size: 12px; margin-top: 10px; }
        .status { padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .status.http { background: #fff3cd; border: 1px solid #ffeaa7; }
        .status.https { background: #d1ecf1; border: 1px solid #bee5eb; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Dummy OAuth Server</h1>
        <p>A simple OAuth 2.0 server for testing and development</p>
    </div>

    <div class="status {{.Protocol}}">
        <strong>Server Status:</strong> Running on {{.Protocol | upper}} | Hostname: {{.Hostname}} | Port: {{.Port}}
    </div>

    <div class="endpoint">
        <h3>Authorization Endpoint</h3>
        <div class="url">{{.BaseURL}}/oauth/authorize</div>
        <div class="description">Start the OAuth flow by redirecting users here</div>
        <div class="example">Example: {{.BaseURL}}/oauth/authorize?client_id=test&redirect_uri=http://localhost:3000/callback&response_type=code&state=xyz&scope=profile%20email</div>
    </div>

    <div class="endpoint">
        <h3>Token Endpoint</h3>
        <div class="url">{{.BaseURL}}/oauth/token</div>
        <div class="description">Exchange authorization code for access token (POST)</div>
        <div class="example">POST with: grant_type=authorization_code&code=AUTH_CODE&redirect_uri=REDIRECT_URI</div>
    </div>

    <div class="endpoint">
        <h3>User Info Endpoint</h3>
        <div class="url">{{.BaseURL}}/oauth/userinfo</div>
        <div class="description">Get user information using access token</div>
        <div class="example">GET with Authorization: Bearer ACCESS_TOKEN</div>
    </div>

    <div class="endpoint">
        <h3>Well-Known Configuration</h3>
        <div class="url">{{.BaseURL}}/.well-known/openid_configuration</div>
        <div class="description">OpenID Connect discovery document</div>
        <div class="example"><a href="{{.BaseURL}}/.well-known/openid_configuration" target="_blank">View Configuration</a></div>
    </div>

    <div class="endpoint">
        <h3>Health Check</h3>
        <div class="url">{{.BaseURL}}/health</div>
        <div class="description">Simple health check endpoint</div>
        <div class="example"><a href="{{.BaseURL}}/health" target="_blank">Check Health</a></div>
    </div>
</body>
</html>
`

func generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func getBaseURL() string {
	scheme := "http"
	if config.TLSCert != "" && config.TLSKey != "" {
		scheme = "https"
	}

	port := config.Port
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		return fmt.Sprintf("%s://%s", scheme, config.Hostname)
	}

	return fmt.Sprintf("%s://%s:%s", scheme, config.Hostname, port)
}

func parseScopes(scopeRaw string) []string {
	if scopeRaw == "" {
		return []string{"profile", "email"}
	}
	parts := strings.Fields(scopeRaw)
	if len(parts) == 0 {
		return []string{"profile", "email"}
	}
	return parts
}

// Root handler to display server information and endpoints
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		logger.Printf("Invalid method %s for / from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logger.Printf("Index page accessed from %s", r.RemoteAddr)

	baseURL := getBaseURL()
	protocol := "http"
	if config.TLSCert != "" && config.TLSKey != "" {
		protocol = "https"
	}

	tmpl := template.Must(template.New("index").Funcs(template.FuncMap{
		"upper": func(s string) string {
			if s == "https" {
				return "HTTPS"
			}
			return "HTTP"
		},
	}).Parse(indexPageHTML))

	data := struct {
		BaseURL  string
		Protocol string
		Hostname string
		Port     string
	}{
		BaseURL:  baseURL,
		Protocol: protocol,
		Hostname: config.Hostname,
		Port:     config.Port,
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		logger.Printf("Invalid method %s for /oauth/authorize from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	clientID := r.URL.Query().Get("client_id")
	state := r.URL.Query().Get("state")
	scopeRaw := r.URL.Query().Get("scope")
	scopes := parseScopes(scopeRaw)

	if redirectURI == "" || clientID == "" {
		logger.Printf("Missing required parameters in authorization request from %s (client_id=%s, redirect_uri=%s)",
			r.RemoteAddr, clientID, redirectURI)
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	logger.Printf("Authorization request: client_id=%s, redirect_uri=%s, scopes=%v, remote_addr=%s",
		clientID, redirectURI, scopes, r.RemoteAddr)

	tmpl := template.Must(template.New("login").Parse(loginPageHTML))
	data := struct {
		RedirectURI string
		ClientID    string
		State       string
		ScopesRaw   string
		Scopes      []string
	}{
		RedirectURI: redirectURI,
		ClientID:    clientID,
		State:       state,
		ScopesRaw:   strings.Join(scopes, " "),
		Scopes:      scopes,
	}

	w.Header().Set("Content-Type", "text/html")
	tmpl.Execute(w, data)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		logger.Printf("Invalid method %s for /oauth/login from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()

	redirectURI := r.FormValue("redirect_uri")
	state := r.FormValue("state")
	scopesRaw := r.FormValue("scopes")
	scopes := parseScopes(scopesRaw)

	userFields := make(map[string]string)
	missing := false
	for _, scope := range scopes {
		val := r.FormValue(scope)
		if val == "" {
			missing = true
			logger.Printf("Missing required field '%s' in login form from %s", scope, r.RemoteAddr)
			break
		}
		userFields[scope] = val
	}

	if redirectURI == "" || missing {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	userData := UserData{
		Fields: userFields,
		Scopes: scopes,
	}

	// Generate authorization code
	authCode := generateRandomString(16)

	// Store auth code data with scopes
	authCodes[authCode] = AuthCodeData{
		RedirectURI: redirectURI,
		UserData:    userData,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Scopes:      scopes,
	}

	logger.Printf("Authorization code generated: code=%s, user=%+v, redirect_uri=%s, remote_addr=%s",
		authCode, userData, redirectURI, r.RemoteAddr)

	// Build redirect URL
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		logger.Printf("Invalid redirect URI: %s from %s", redirectURI, r.RemoteAddr)
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	query := redirectURL.Query()
	query.Set("code", authCode)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	logger.Printf("Redirecting user to: %s", redirectURL.String())
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		logger.Printf("Invalid method %s for /oauth/token from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()

	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")

	if grantType != "authorization_code" {
		logger.Printf("Unsupported grant type: %s from %s", grantType, r.RemoteAddr)
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	if code == "" {
		logger.Printf("Missing authorization code in token request from %s", r.RemoteAddr)
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Validate auth code
	authData, exists := authCodes[code]
	if !exists {
		logger.Printf("Invalid authorization code: %s from %s", code, r.RemoteAddr)
		http.Error(w, "Invalid authorization code", http.StatusBadRequest)
		return
	}

	// Check if code expired
	if time.Now().After(authData.ExpiresAt) {
		delete(authCodes, code)
		logger.Printf("Expired authorization code: %s from %s", code, r.RemoteAddr)
		http.Error(w, "Authorization code expired", http.StatusBadRequest)
		return
	}

	// Validate redirect URI
	if redirectURI != "" && redirectURI != authData.RedirectURI {
		logger.Printf("Redirect URI mismatch: expected=%s, got=%s from %s",
			authData.RedirectURI, redirectURI, r.RemoteAddr)
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	// Generate access token
	accessToken := generateRandomString(32)

	// Store user data with access token
	accessTokens[accessToken] = authData.UserData

	// Delete used auth code
	delete(authCodes, code)

	logger.Printf("Access token issued: user=%+v, remote_addr=%s",
		authData.UserData, r.RemoteAddr)

	response := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600, // 1 hour
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		logger.Printf("Invalid method %s for /oauth/userinfo from %s", r.Method, r.RemoteAddr)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		logger.Printf("Missing authorization header in userinfo request from %s", r.RemoteAddr)
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	// Extract bearer token
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		logger.Printf("Invalid authorization header format from %s", r.RemoteAddr)
		http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	accessToken := authHeader[7:]

	// Look up user data
	userData, exists := accessTokens[accessToken]
	if !exists {
		logger.Printf("Invalid access token used from %s", r.RemoteAddr)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	logger.Printf("User info requested: user=%+v, remote_addr=%s", userData, r.RemoteAddr)

	// Return only the fields that were in the authorized scopes
	resp := UserInfoResponse{}
	for _, scope := range userData.Scopes {
		if val, ok := userData.Fields[scope]; ok {
			resp[scope] = val
		}
	}
	// Set "sub" field for OIDC compatibility
	if email, ok := resp["email"]; ok && email != "" {
		resp["sub"] = email
	} else if profile, ok := resp["profile"]; ok && profile != "" {
		resp["sub"] = profile
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Well-known configuration endpoint
func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	logger.Printf("Well-known configuration accessed from %s", r.RemoteAddr)

	baseURL := getBaseURL()

	config := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"userinfo_endpoint":                     baseURL + "/oauth/userinfo",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"scopes_supported":                      []string{"profile", "email"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func main() {
	// Load configuration
	config = loadConfig()

	// Initialize logger
	initLogger()

	// Validate TLS configuration
	tlsEnabled := config.TLSCert != "" && config.TLSKey != ""
	if (config.TLSCert != "" && config.TLSKey == "") || (config.TLSCert == "" && config.TLSKey != "") {
		logger.Fatal("Both TLS_CERT and TLS_KEY must be provided for TLS support")
	}

	logger.Printf("Server starting with configuration: bind_ip=%s, port=%s, hostname=%s, tls_enabled=%t",
		config.BindIP, config.Port, config.Hostname, tlsEnabled)

	// CORS middleware to allow requests from any origin
	corsMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next(w, r)
		}
	}

	// OAuth endpoints
	http.HandleFunc("/", corsMiddleware(indexHandler))
	http.HandleFunc("/oauth/authorize", corsMiddleware(authHandler))
	http.HandleFunc("/oauth/login", corsMiddleware(loginHandler))
	http.HandleFunc("/oauth/token", corsMiddleware(tokenHandler))
	http.HandleFunc("/oauth/userinfo", corsMiddleware(userinfoHandler))
	http.HandleFunc("/.well-known/openid_configuration", corsMiddleware(wellKnownHandler))

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		logger.Printf("Health check from %s", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	listenAddr := config.BindIP + ":" + config.Port
	baseURL := getBaseURL()

	fmt.Printf("Dummy OAuth Server Configuration:\n")
	fmt.Printf("  Bind Address: %s\n", listenAddr)
	fmt.Printf("  Hostname: %s\n", config.Hostname)
	fmt.Printf("  TLS Enabled: %t\n", tlsEnabled)
	fmt.Printf("\nEndpoints:\n")
	fmt.Printf("  Authorization: %s/oauth/authorize\n", baseURL)
	fmt.Printf("  Token:         %s/oauth/token\n", baseURL)
	fmt.Printf("  UserInfo:      %s/oauth/userinfo\n", baseURL)
	fmt.Printf("  Well-known:    %s/.well-known/openid_configuration\n", baseURL)
	fmt.Printf("  Health:        %s/health\n", baseURL)

	server := &http.Server{
		Addr: listenAddr,
	}

	if tlsEnabled {
		// Configure TLS
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		logger.Printf("Starting HTTPS server on %s", listenAddr)
		fmt.Printf("Dummy OAuth Server starting on HTTPS %s...\n", listenAddr)
		log.Fatal(server.ListenAndServeTLS(config.TLSCert, config.TLSKey))
	} else {
		logger.Printf("Starting HTTP server on %s", listenAddr)
		fmt.Printf("Dummy OAuth Server starting on HTTP %s...\n", listenAddr)
		log.Fatal(server.ListenAndServe())
	}
}
