# Dummy OAuth Server

A simple OAuth 2.0 server written in Go for testing and development purposes. This server provides a complete OAuth authorization flow without requiring real user authentication - perfect for testing OAuth integrations.

## Features

- Complete OAuth 2.0 authorization code flow
- Simple name/email form instead of real authentication
- Accepts any client ID and redirect URI
- HTTPS/TLS support
- CORS enabled for cross-origin requests
- OpenID Connect discovery endpoint
- Web interface showing all endpoints

## Quick Start

```bash
# Run with default settings (localhost:8080)
go run main.go

# Run on custom port
PORT=9080 go run main.go

# Run with HTTPS
TLS_CERT=/path/to/cert.pem TLS_KEY=/path/to/key.pem go run main.go
```

Visit `http://localhost:8080` to see all available endpoints.

## Configuration

Configure the server using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BIND_IP` | IP address to bind to | `127.0.0.1` |
| `PORT` | Port to listen on | `8080` |
| `OAUTH_HOSTNAME` | Public hostname for URLs | `localhost` |
| `TLS_CERT` | Path to TLS certificate file | (none) |
| `TLS_KEY` | Path to TLS private key file | (none) |

## Usage

### Authorization Flow

1. **Start Authorization**: Redirect users to the authorization endpoint:
   ```
   http://localhost:8080/oauth/authorize?client_id=your-app&redirect_uri=http://your-app.com/callback&response_type=code&state=random-string
   ```

2. **User "Login"**: Users will see a simple form asking for name and email (no real authentication required)

3. **Get Authorization Code**: After form submission, users are redirected to your callback URL with an authorization code:
   ```
   http://your-app.com/callback?code=abc123&state=random-string
   ```

4. **Exchange for Token**: POST to the token endpoint to get an access token:
   ```bash
   curl -X POST http://localhost:8080/oauth/token \
     -d "grant_type=authorization_code" \
     -d "code=abc123" \
     -d "redirect_uri=http://your-app.com/callback"
   ```

5. **Get User Info**: Use the access token to get user information:
   ```bash
   curl -H "Authorization: Bearer your-access-token" \
     http://localhost:8080/oauth/userinfo
   ```

## Endpoints

- `GET /` - Web interface showing all endpoints
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token exchange endpoint
- `GET /oauth/userinfo` - User information endpoint
- `GET /.well-known/openid_configuration` - OpenID Connect discovery
- `GET /health` - Health check

## Example Configuration

```bash
# Development setup
PORT=8080 go run main.go

# Production-like setup with HTTPS
BIND_IP=0.0.0.0 \
PORT=443 \
OAUTH_HOSTNAME=oauth.yourdomain.com \
TLS_CERT=/etc/ssl/certs/oauth.crt \
TLS_KEY=/etc/ssl/private/oauth.key \
go run main.go
```

## Requirements

- Go 1.19 or later
- Optional: TLS certificate and key files for HTTPS

## Security Notice

⚠️ **This is a dummy server for testing only!** It accepts any credentials and should never be used in production. All data is stored in memory and will be lost when the server restarts.