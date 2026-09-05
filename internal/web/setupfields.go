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
	// fieldProfiles is a setting whose value is a JSON object of sender
	// address to capabilities, asked for as one row of boxes per profile:
	// nobody should have to type JSON by hand to say what a printer button
	// is allowed to do.
	fieldProfiles fieldKind = "profiles"
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
	// Placeholder is a synthetic example shown in an empty box, so the shape
	// of an answer needs no sentence of its own. It never shows once Set is
	// true: what the box then has to say is that something is configured,
	// not what one might look like.
	Placeholder string
}

// groupIdentity is the one card the wizard has more to say about than a
// sentence: entraSteps hangs the app-registration walkthrough off this name,
// so renaming the card moves the walkthrough with it.
const groupIdentity = "Identity"

// setupFields is every S2G_* setting a real deployment might set, in the
// order the form asks for them. handEdited below covers the rest. A test
// keeps the two lists and the loader in step: a new setting without an entry
// in either fails that test rather than quietly becoming unreachable through
// the wizard.
var setupFields = []setupField{
	{
		Name: "S2G_GRAPH_SENDER", Label: "Sending mailbox", Group: "Email delivery",
		Help:        "The mailbox scans are mailed from; setting it together with the allowlist below is what turns email delivery on.",
		Placeholder: "scanner@example.com",
	}, {
		Name: "S2G_ALLOWED_RECIPIENT_DOMAINS", Label: "Allowed recipient domains", Group: "Email delivery",
		Help:        "Comma-separated domains a scan may be mailed to, without a leading @ and matched exactly; email delivery requires it, or the appliance would be an open relay.",
		Placeholder: "example.com, example.org",
	}, {
		Name: "S2G_PUBLIC_BASE_URL", Label: "Public URL", Group: "Browser downloads",
		Help:        "Where this appliance is reached through the reverse proxy that terminates TLS; setting it is what turns the web UI on. A host of its own, or a subpath under a shared one (https://nas.acme.office/scanner/) that the proxy forwards unchanged.",
		Placeholder: "https://scan2graph.example.com",
	}, {
		Name: "S2G_UI_TITLE", Label: "Name shown in the UI", Group: "Browser downloads", Rare: true,
		Help:        "What the web UI calls itself in its title and header, so it can say the household's or the office's name.",
		Placeholder: "scan2graph",
	}, {
		Name: "S2G_JOB_TTL", Label: "How long a scan stays available", Group: "Browser downloads", Rare: true,
		Help:        "How long a scan can be downloaded before it and its files are deleted; must be at least 1m.",
		Placeholder: "8h",
	}, {
		Name: "S2G_HTTP_ADDR", Label: "HTTP listen address", Group: "Browser downloads", Rare: true,
		Help:        "Address this process listens on for HTTP. In a container, this is internal; publish it through the host or reverse proxy rather than using it as the public URL.",
		Placeholder: ":8080",
	}, {
		Name: "S2G_DI_ENDPOINT", Label: "Document Intelligence endpoint", Group: "Text recognition",
		Help:        "The https URL of the Azure Document Intelligence resource that makes scans searchable; setting it is what turns text recognition on.",
		Placeholder: "https://example.cognitiveservices.azure.com",
	}, {
		Name: "S2G_ENTRA_TENANT_ID", Label: "Directory (tenant) ID", Group: groupIdentity,
		Help:        "The Directory (tenant) ID on the app registration's Overview page in the Azure portal.",
		Placeholder: "00000000-0000-0000-0000-000000000000",
	}, {
		Name: "S2G_ENTRA_CLIENT_ID", Label: "Application (client) ID", Group: groupIdentity,
		Help:        "The Application (client) ID on that same Overview page.",
		Placeholder: "00000000-0000-0000-0000-000000000000",
	}, {
		Name: "S2G_ENTRA_CLIENT_SECRET", Label: "Client secret", Kind: fieldSecret, Group: groupIdentity,
		Help: "The secret's Value (not its Secret ID) under Certificates & secrets in that app registration, which the portal shows only once, right after you create it.",
	}, {
		Name: "S2G_SMTP_USERNAME", Label: "SMTP username", Group: "Scanner",
		Help:        "Username the printer signs in with; only means anything once a password is set.",
		Placeholder: "scanner",
	}, {
		Name: "S2G_SMTP_PASSWORD", Label: "SMTP password", Kind: fieldSecret, Group: "Scanner",
		Help: "Password the printer signs in with. Use Generate SMTP password below to create or replace it, then Save or Download to keep it across restarts. If left unset, a new one is made on every start.",
	}, {
		Name: "S2G_SMTP_ALLOW_ANONYMOUS", Label: "Accept scans without SMTP AUTH", Kind: fieldBool, Group: "Scanner",
		Help: "For a printer that cannot authenticate at all: only on a trusted, isolated network segment, and not together with a username or password.",
	}, {
		Name: "S2G_SMTP_ADDR", Label: "SMTP listen address", Group: "Scanner", Rare: true,
		Help:        "Address this process listens on for SMTP. In a container, the printer connects to the appliance host on the LAN and the port published to this address.",
		Placeholder: ":2525",
	}, {
		Name: "S2G_PROFILES", Label: "Printer profiles", Kind: fieldProfiles, Group: "Scanner", Rare: true,
		Help: "One row per address the printer sends from, ticking what a scan from that address may do; with no rows filled in there are no profiles at all, and then every sender is accepted and gets whatever the rest of this configuration enables. Type into the blank rows to add profiles; two fresh ones come back with every submission the appliance accepts.",
	}, {
		Name: "S2G_MAX_MESSAGE_BYTES", Label: "Largest accepted message", Group: "Scanner", Rare: true,
		Help:        "Biggest message the SMTP listener accepts, in bytes; the default is 32 MiB.",
		Placeholder: "33554432",
	}, {
		Name: "S2G_LOG_LEVEL", Label: "Log level", Kind: fieldChoice,
		Choice: []string{"debug", "info", "warn", "error"}, Group: "Advanced", Rare: true,
		Help: "How much scan2graph writes to its log; defaults to info.",
	}, {
		Name: "S2G_LOG_FORMAT", Label: "Log format", Kind: fieldChoice,
		Choice: []string{"json", "text"}, Group: "Advanced", Rare: true,
		Help: "json for a log collector, text for reading it yourself; defaults to json.",
	}, {
		Name: "S2G_TEMP_DIR", Label: "Temporary directory", Group: "Advanced", Rare: true,
		Help:        "Where scans are kept while they are worked on; it is wiped on every start and defaults to the operating system's temp directory.",
		Placeholder: "/tmp",
	}, {
		Name: "S2G_MAX_JOBS", Label: "Most scans kept at once", Group: "Advanced", Rare: true,
		Help:        "How many scans may be queued, in flight or waiting to be picked up together.",
		Placeholder: "32",
	}, {
		Name: "S2G_MAX_CONCURRENT_JOBS", Label: "Scans processed at once", Group: "Advanced", Rare: true,
		Help:        "How many scans are worked on at the same time.",
		Placeholder: "2",
	},
}

// groupIntro is the sentence a card opens with: what it is for in the
// operator's terms, and why they would want it - which is the half no
// field's own Help answers, because a Help says what a setting does. Keyed
// by the Group name above rather than carried on every field, where it
// would be the same sentence to keep in step three or four times over.
// A card whose fields already say it between them gets none, and neither
// does Advanced: it stays folded away, and whoever opens it knows what
// they came for.
var groupIntro = map[string]string{
	"Email delivery":    "Set both fields to mail scans.",
	"Browser downloads": "Set the public URL to let people pick scans up in a browser.",
	"Text recognition":  "Optional: with a Document Intelligence resource, scans come out as PDFs you can search rather than pictures of paper.",
	groupIdentity:       "Required for every setup. One Entra app registration signs people in to browser downloads and supplies the tokens used for email and text recognition.",
	"Scanner":           "Set how the printer authenticates. In a container, it connects to the appliance's published host and port on the LAN.",
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
