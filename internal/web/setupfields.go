package web

// fieldKind is how a setting is asked for, and how a blank answer reads back.
// It is a string so the template can switch on it without knowing the
// numbering of a constant.
type fieldKind string

const (
	fieldText   fieldKind = "text"
	fieldSecret fieldKind = "secret"
	fieldBool   fieldKind = "bool"
	fieldChoice fieldKind = "choice"
	fieldArea   fieldKind = "area"
)

// setupField is one setting as the wizard asks for it. Help is one sentence,
// in the operator's words rather than the loader's, and names where in the
// Azure portal the value comes from wherever that is the part people get
// stuck on.
type setupField struct {
	Name, Label, Help string
	Kind              fieldKind
	Choice            []string // fieldChoice only
	Group             string   // fieldset heading
	Rare              bool     // renders inside the group's <details> block
}

// setupFields is every S2G_* setting a real deployment might set, in the
// order the form asks for them. handEdited below covers the rest. A test
// keeps the two lists and the loader in step: a new setting without an entry
// in either fails that test rather than quietly becoming unreachable through
// the wizard.
var setupFields = []setupField{
	{
		Name: "S2G_ENTRA_TENANT_ID", Label: "Directory (tenant) ID", Group: "Identity",
		Help: "The Directory (tenant) ID on the app registration's Overview page in the Azure portal, e.g. 00000000-0000-0000-0000-000000000000.",
	}, {
		Name: "S2G_ENTRA_CLIENT_ID", Label: "Application (client) ID", Group: "Identity",
		Help: "The Application (client) ID on that same Overview page.",
	}, {
		Name: "S2G_ENTRA_CLIENT_SECRET", Label: "Client secret", Kind: fieldSecret, Group: "Identity",
		Help: "The secret's Value (not its Secret ID) under Certificates & secrets in that app registration, which the portal shows only once, right after you create it.",
	}, {
		Name: "S2G_GRAPH_SENDER", Label: "Sending mailbox", Group: "Delivery",
		Help: "The mailbox scans are mailed from, e.g. scanner@example.com; setting it together with the allowlist below is what turns email delivery on.",
	}, {
		Name: "S2G_ALLOWED_RECIPIENT_DOMAINS", Label: "Allowed recipient domains", Group: "Delivery",
		Help: "Comma-separated domains a scan may be mailed to, without a leading @ and matched exactly, e.g. example.com; email delivery requires it, or the appliance would be an open relay.",
	}, {
		Name: "S2G_RECIPIENT_ALIASES", Label: "Recipient aliases", Kind: fieldArea, Group: "Delivery",
		Help: `JSON object mapping a shorthand address the printer's address book can hold to the real one, e.g. {"printer-shortcut@scanner.local":"jane.doe@example.com"}.`,
	}, {
		Name: "S2G_PUBLIC_BASE_URL", Label: "Public URL", Group: "Web UI",
		Help: "Where this appliance is reached through the reverse proxy that terminates TLS, e.g. https://scan2graph.example.com; setting it is what turns the web UI on, and it must address the root of a host of its own.",
	}, {
		Name: "S2G_UI_TITLE", Label: "Name shown in the UI", Group: "Web UI",
		Help: "What the web UI calls itself in its title and header, so it can say the household's or the office's name; defaults to scan2graph.",
	}, {
		Name: "S2G_JOB_TTL", Label: "How long a scan stays available", Group: "Web UI",
		Help: "How long a scan can be downloaded before it and its files are deleted, written like 90m or 2h and at least 1m.",
	}, {
		Name: "S2G_HTTP_ADDR", Label: "HTTP listen address", Group: "Web UI", Rare: true,
		Help: "Address the web UI listens on inside the container; defaults to :8080.",
	}, {
		Name: "S2G_SMTP_ADDR", Label: "SMTP listen address", Group: "Scanner",
		Help: "Address the printer sends its scans to; defaults to :2525.",
	}, {
		Name: "S2G_SMTP_USERNAME", Label: "SMTP username", Group: "Scanner",
		Help: "Username the printer signs in with; defaults to scanner, and only means anything once a password is set.",
	}, {
		Name: "S2G_SMTP_PASSWORD", Label: "SMTP password", Kind: fieldSecret, Group: "Scanner",
		Help: "Password the printer signs in with; leave it unset and scan2graph makes up a new one on every start, which means reconfiguring the printer after every restart.",
	}, {
		Name: "S2G_SMTP_ALLOW_ANONYMOUS", Label: "Accept scans without SMTP AUTH", Kind: fieldBool, Group: "Scanner",
		Help: "For a printer that cannot authenticate at all: only on a trusted, isolated network segment, and not together with a username or password.",
	}, {
		Name: "S2G_PROFILES", Label: "Sender profiles", Kind: fieldArea, Group: "Scanner", Rare: true,
		Help: `JSON object giving each printer sender address the features it may use, e.g. {"scan-web@scanner.local":{"email":false,"web":true,"ocr":true}}; leave it empty and every sender gets whatever the settings above enable.`,
	}, {
		Name: "S2G_MAX_MESSAGE_BYTES", Label: "Largest accepted message", Group: "Scanner", Rare: true,
		Help: "Biggest message the SMTP listener accepts, in bytes; defaults to 33554432, which is 32 MiB.",
	}, {
		Name: "S2G_DI_ENDPOINT", Label: "Document Intelligence endpoint", Group: "Text recognition",
		Help: "The https URL of the Azure Document Intelligence resource that makes scans searchable, e.g. https://replace-me.cognitiveservices.azure.com; setting it is what turns text recognition on.",
	}, {
		Name: "S2G_LOG_LEVEL", Label: "Log level", Kind: fieldChoice,
		Choice: []string{"debug", "info", "warn", "error"}, Group: "Advanced",
		Help: "How much scan2graph writes to its log; defaults to info.",
	}, {
		Name: "S2G_LOG_FORMAT", Label: "Log format", Kind: fieldChoice,
		Choice: []string{"json", "text"}, Group: "Advanced",
		Help: "json for a log collector, text for reading it yourself; defaults to json.",
	}, {
		Name: "S2G_TEMP_DIR", Label: "Temporary directory", Group: "Advanced", Rare: true,
		Help: "Where scans are kept while they are worked on; it is wiped on every start and defaults to the operating system's temp directory.",
	}, {
		Name: "S2G_MAX_JOBS", Label: "Most scans kept at once", Group: "Advanced", Rare: true,
		Help: "How many scans may be queued, in flight or waiting to be picked up together; defaults to 32.",
	}, {
		Name: "S2G_MAX_CONCURRENT_JOBS", Label: "Scans processed at once", Group: "Advanced", Rare: true,
		Help: "How many scans are worked on at the same time; defaults to 2.",
	},
}

// handEdited are S2G_* settings that exist only for the end-to-end test
// harness, to point the appliance at a fake Entra, Graph or Document
// Intelligence server. No real deployment sets them, so they get no box on
// the form; an operator who somehow needs one edits the configuration file
// by hand. TestSetupFieldsCoverConfig still has to see them, so a name the
// loader reads is never missing from both lists at once.
var handEdited = []string{
	"S2G_ENTRA_AUTHORITY_URL",
	"S2G_ENTRA_TOKEN_URL",
	"S2G_GRAPH_BASE_URL",
	"S2G_GRAPH_SCOPE",
	"S2G_DI_API_VERSION",
	"S2G_DI_SCOPE",
}

// protected are the settings whose presence means there is something here
// worth taking: the Entra app registration this appliance signs in as, and
// the two secrets. Deliberately not every name on the form - the question an
// unauthenticated wizard turns on is "is there a secret here to steal", not
// "has anybody touched anything", and a listen address or a log level is not
// that. Counting one of those would mean a genuinely blank appliance with
// S2G_HTTP_ADDR set never gets its first-boot wizard, and that the wizard
// could only ever be reached on the default port.
var protected = []string{
	"S2G_ENTRA_TENANT_ID",
	"S2G_ENTRA_CLIENT_ID",
	"S2G_ENTRA_CLIENT_SECRET",
	"S2G_SMTP_PASSWORD",
}

// AnyConfigured reports whether any of protected resolves non-empty in either
// spelling. It is the one rule behind both of the wizard's unauthenticated
// doors: main opens the first-boot wizard without a token only when the
// answer is no, and mints one for "setup" exactly when it is yes. A
// half-configured appliance - the identity present, the secret's mount gone -
// answers yes and stays an error exit rather than an open configuration
// editor on the LAN.
func AnyConfigured(getenv func(string) string) bool {
	for _, name := range protected {
		if getenv(name) != "" || getenv(name+"_FILE") != "" {
			return true
		}
	}
	return false
}
