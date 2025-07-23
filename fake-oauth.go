// ... (imports and config unchanged)

type UserData struct {
	Fields map[string]string // Maps scope name to user-provided value
	Scopes []string
}

type AuthCodeData struct {
	RedirectURI string
	UserData    UserData
	ExpiresAt   time.Time
	Scopes      []string
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

// ... indexPageHTML unchanged

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

// ... wellKnownHandler and main unchanged
