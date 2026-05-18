package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity"
	owjwt "github.com/marcosfpina/O.W.A.S.A.K.A/internal/identity/jwt"
	"github.com/marcosfpina/O.W.A.S.A.K.A/pkg/logging"
)

// LoginHandlerDeps bundles the services needed by the login endpoint.
type LoginHandlerDeps struct {
	Authenticator  identity.Authenticator
	Issuer         *owjwt.Issuer
	PrincipalStore identity.PrincipalStore
	Logger         *logging.Logger
}

// LoginHandler returns an http.Handler that authenticates a user via
// password+TOTP and returns a JWT access+refresh pair.
//
// POST /auth/login
//
//	Content-Type: application/json
//	Body: {"username":"...", "password":"...", "totp":"..."}
//
// Success 200: {"access_token":"...", "refresh_token":"...", "principal":{...}}
// Failure 401: {"error":"..."}
func LoginHandler(deps LoginHandlerDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeLoginError(w, "invalid request body", http.StatusBadRequest, deps.Logger)
			return
		}
		if req.Username == "" || req.Password == "" || req.TOTP == "" {
			writeLoginError(w, "username, password, and totp are required", http.StatusBadRequest, deps.Logger)
			return
		}

		factors := []identity.AuthFactor{
			{
				Kind:    identity.CredentialPassword,
				Subject: req.Username,
				Proof:   []byte(req.Password),
			},
			{
				Kind:    identity.CredentialPassword,
				Subject: req.Username,
				Proof:   []byte(req.Password),
				Extra:   map[string]any{"totp": req.TOTP},
			},
		}

		p, err := deps.Authenticator.Authenticate(r.Context(), factors)
		if err != nil {
			writeLoginError(w, "authentication failed", http.StatusUnauthorized, deps.Logger)
			if deps.Logger != nil {
				deps.Logger.Debugw("login rejected",
					"username", req.Username,
					"remote", r.RemoteAddr,
					"reason", err.Error(),
				)
			}
			return
		}

		pair, err := deps.Issuer.Issue(r.Context(), p)
		if err != nil {
			writeLoginError(w, "token issuance failed", http.StatusInternalServerError, deps.Logger)
			if deps.Logger != nil {
				deps.Logger.Errorw("login: token issuance failed", "principal_id", p.ID, "error", err)
			}
			return
		}

		// Update last seen timestamp (best-effort, non-blocking).
		if deps.PrincipalStore != nil {
			now := time.Now()
			_ = deps.PrincipalStore.UpdateLastSeen(r.Context(), p.ID, now)
		}

		if deps.Logger != nil {
			deps.Logger.Infow("login succeeded",
				"principal_id", p.ID,
				"username", req.Username,
				"remote", r.RemoteAddr,
			)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  pair.AccessToken,
			"refresh_token": pair.RefreshToken,
			"expires_in":    int(time.Until(pair.AccessExp).Seconds()),
			"principal":     p,
		})
	}
}

func writeLoginError(w http.ResponseWriter, msg string, status int, logger *logging.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
