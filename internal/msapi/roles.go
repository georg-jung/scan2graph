package msapi

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// TokenRoles lists the application permissions an app-only access token was
// issued for: Entra puts them in the JWT's "roles" claim, so the appliance
// can learn what it may do without asking the operator to configure it
// twice. It is pure and offline - the token is a bearer credential this
// process already holds and already trusts, so there is nothing here to
// verify, and no signature check to imply otherwise.
//
// Anything that is not a readable JWT payload yields nil rather than an
// error: the only caller wants "is this permission granted", and every way
// of failing to answer that means no.
//
// Never log the token, and never log what this decodes. A decoded claim set
// is not a secret the way the token is, but it is the token's contents; the
// startup banner names the one role it cares about and nothing else.
func TokenRoles(accessToken string) []string {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil
	}
	// RawURLEncoding: JWS segments are base64url without padding (RFC 7515).
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		Roles []string `json:"roles"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return nil
	}
	return claims.Roles
}
