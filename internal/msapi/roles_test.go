package msapi

import (
	"encoding/base64"
	"slices"
	"testing"
)

// fakeSignature is the only credential-shaped literal in this file. Nothing
// here verifies a signature -- TokenRoles does not either -- so one
// obviously synthetic value stands in for every token's third segment.
const fakeSignature = "not-a-real-signature"

// fakeJWT assembles a token with the given payload, the way Entra hands one
// out: three base64url segments, unpadded, joined with dots.
func fakeJWT(payload string) string {
	seg := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return seg(`{"alg":"RS256","typ":"JWT"}`) + "." + seg(payload) + "." + seg(fakeSignature)
}

func TestTokenRoles(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  []string
	}{
		{
			name:  "app-only token lists its granted permissions",
			token: fakeJWT(`{"aud":"https://graph.example","appid":"00000000-0000-0000-0000-000000000000","roles":["Mail.Send","Mail.ReadWrite"]}`),
			want:  []string{"Mail.Send", "Mail.ReadWrite"},
		},
		{"no roles claim", fakeJWT(`{"aud":"https://graph.example","scp":"Mail.Send"}`), nil},
		{"empty token", "", nil},
		{"payload is not base64url", "aaa.not base64!.bbb", nil},
		{"payload is not JSON", fakeJWT("nothing json about this"), nil},
		{"roles is not an array of strings", fakeJWT(`{"roles":"Mail.Send"}`), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TokenRoles(tt.token); !slices.Equal(got, tt.want) {
				t.Errorf("TokenRoles() = %v, want %v", got, tt.want)
			}
		})
	}
}
