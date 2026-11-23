package config

import (
	"slices"
	"strings"
)

// Settings is every S2G_* name Load reads. TestSetupFieldsCoverConfig keeps
// it in step with the loader.
var Settings = []string{
	"S2G_ALLOWED_RECIPIENT_DOMAINS", "S2G_DI_ENDPOINT", "S2G_ENTRA_AUTHORITY_URL",
	"S2G_ENTRA_CLIENT_ID", "S2G_ENTRA_CLIENT_SECRET", "S2G_ENTRA_TENANT_ID",
	"S2G_GRAPH_BASE_URL", "S2G_GRAPH_SENDER", "S2G_HTTP_ADDR", "S2G_JOB_TTL",
	"S2G_LOG_LEVEL", "S2G_MAX_MESSAGE_BYTES", "S2G_MAX_STORED_BYTES",
	"S2G_PUBLIC_BASE_URL", "S2G_SMTP_ADDR", "S2G_SMTP_ALLOW_ANONYMOUS", "S2G_SMTP_PASSWORD",
}

// Unknown returns, sorted, the S2G_-prefixed names among the file's keys and
// the environ ("KEY=value") entries that neither Load nor main reads.
func Unknown(file map[string]string, environ []string) []string {
	var out []string
	add := func(name string) {
		if strings.HasPrefix(name, "S2G_") && name != "S2G_CONFIG_FILE" &&
			!slices.Contains(Settings, name) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	for name := range file {
		add(name)
	}
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		add(name)
	}
	slices.Sort(out)
	return out
}
