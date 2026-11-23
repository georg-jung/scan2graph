package web

import (
	"cmp"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/georg-jung/scan2graph/internal/config"
)

// The setup wizard: the one page that writes the configuration file the rest
// of this appliance reads. It is a separate handler, not a route of the UI, so
// a serving appliance has no setup routes in existence rather than guarded
// ones. What it shares with the UI is the layout, the stylesheet, the CSP and
// the security headers.

const (
	setupCookie = "s2g_setup"
	// setupFormLimit bounds a submission; a whole configuration is a few
	// hundred bytes.
	setupFormLimit = 64 << 10
	// setupFileName is what a downloaded configuration file is called, and
	// what the README tells the operator to mount.
	setupFileName = "scan2graph.env"
	// setupFormsKept is how many rendered forms remember what was typed into
	// them, oldest falling off first: the operator is looking at the newest,
	// and growth on a page nobody else can reach is still growth.
	setupFormsKept = 4
)

var setupTmpl = mustParse("setup.html")

// SetupOptions configures the wizard.
type SetupOptions struct {
	Getenv     func(string) string // effective process environment (os.Getenv in production)
	FileValues map[string]string   // the configuration file as it is now; nil when there is none
	Path       string              // where Save writes; "" means download-only
	TokenHash  []byte              // SHA-256 of the one-shot token; nil offers the wizard to whoever claims it first
	OnSaved    func()              // optional nonblocking signal after a successful save response is rendered, outside the save lock
}

type setupServer struct {
	SetupOptions
	// prefix is the subpath the wizard is published under, "" for a host of
	// the appliance's own. It is read once, from the configuration a package
	// installer seeded before first boot, because a request cannot tell a
	// proxy that forwards /scan2graph from a direct hit on that path - and on
	// a NAS the proxy is how the operator first meets the wizard, when
	// nothing else is configured yet. A prefix saved *in* the wizard applies
	// at the restart that applies everything else it wrote.
	prefix string
	// pending is what each rendered form handed back, newest last and keyed
	// by that render's id; remember says why it exists and why it is per page.
	pending []pendingForm
	// file counts how many times a save has replaced FileValues, so a fold
	// can say which file it was taken from.
	file uint64
	// mu guards FileValues and pending, which a successful save replaces
	// while other request goroutines are rendering the form from them, and
	// TokenHash, which every request reads and start writes exactly once.
	// They are not coupled to each other: the door closes when the wizard is
	// claimed, long before there is any way to save anything, so all the
	// mutex does for the values is hand a reader one whole map rather than
	// half of two - no security answer turns on the order in which a save and
	// the gate become visible.
	mu sync.Mutex
}

// pendingForm is one rendered page: the id it hands back, and what it shows.
type pendingForm struct {
	id     string
	values map[string]string
	// file is what FileValues had been replaced how many times when these
	// values were folded. A fold is only good while the file it folded into
	// is unchanged: a save during a slow "Test the connection" makes that
	// test's answer stale, however new the page carrying it looks.
	file uint64
}

// NewSetup returns a handler serving the wizard and nothing else: the form,
// the claim page in front of it, the stylesheet they need, and a 404 for
// everything else. Mount /healthz and /readyz above it, exactly as in serve
// mode.
//
// Under a subpath prefix the wizard lives entirely under it, exactly like the
// appliance it configures - one mount, so the claim that makes the wizard one
// browser's cannot exist twice - and the bare address redirects there, since
// the one thing on the other end of it is a human who can be sent along.
func NewSetup(opts SetupOptions) http.Handler {
	s := &setupServer{SetupOptions: opts}
	s.prefix = config.BasePath(config.ResolveBaseURL(config.Layer(opts.FileValues, opts.Getenv)))
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err) // embedded at build time, cannot fail
	}
	p := s.prefix
	home := http.RedirectHandler(p+"/setup", http.StatusSeeOther)
	mux := http.NewServeMux()
	if p != "" {
		// Where the proxy actually sends someone who opens it: /scan2graph/,
		// and /scan2graph without the slash, which ServeMux redirects here
		// itself. This one is inside the prefix, so the wizard's cookie
		// reaches it.
		mux.Handle("GET "+p+"/{$}", home)
	}
	mux.HandleFunc("GET "+p+"/setup", func(w http.ResponseWriter, r *http.Request) {
		if !s.holder(r) {
			// Nobody has claimed the wizard yet, so this is still the door
			// rather than the room: ask before handing it over, because the
			// answer takes it away from every other browser on the network.
			// The question is holder rather than "is it claimed": that is the
			// same answer while unclaimed - nobody holds a nil hash - and it
			// stays the right one for a request admitted while unclaimed that
			// another browser's press has claimed out from under, which would
			// otherwise be handed the form it holds no key to.
			render(slog.Default(), w, setupTmpl, setupView{
				page: page{Title: "Setup", Base: s.prefix + "/"}, Claim: true,
			})
			return
		}
		current, _ := s.values(nil)
		render(slog.Default(), w, setupTmpl, s.view(current, nil, nil))
	})
	mux.HandleFunc("POST "+p+"/setup/start", s.start)
	mux.HandleFunc("POST "+p+"/setup", s.submit)
	mux.Handle("GET "+p+"/static/", http.StripPrefix(p+"/static/", http.FileServerFS(static)))

	// The bare address is the only thing outside the wizard's subpath, and it
	// is deliberately in front of the gate rather than behind it: all it says
	// is where the wizard is, which is the address the operator configured,
	// and guarding it would be worth having only if the token cookie
	// travelled the whole host - which is precisely what a shared host must
	// not do. Everything that can read or write anything is on the other
	// side. When there is no prefix this is the root route, and the wizard's
	// own /{$} is not registered, so no pattern exists twice.
	root := http.NewServeMux()
	root.Handle("GET /{$}", home)
	root.Handle("/", s.authenticate(mux))
	return secureHeaders(root)
}

// holder reports whether this request carries the key to the wizard as it
// stands. An unclaimed wizard has no key, so nobody holds it - which is what
// keeps "claim the room before you do anything in it" true rather than
// decorative: without this, a crafted POST could write the appliance's
// configuration without anybody having pressed Start. The hash is written
// once and never again, so the answer stays true for the rest of the request.
func (s *setupServer) holder(r *http.Request) bool {
	hash := s.tokenHash()
	if hash == nil {
		return false
	}
	c, err := r.Cookie(setupCookie)
	return err == nil && tokenOK(c.Value, hash)
}

// start is the "Start configuration" button, and the only thing in the whole
// wizard that closes its door. A press is deliberate in a way a GET is not -
// a prefetch, an omnibox guess or a port scanner cannot make one - so the
// browser that presses it is a human who has just been told what it costs:
// the wizard becomes theirs, and everybody else gets the 404 everybody
// without a token gets. Claiming it here, while there is by construction
// nothing configured to disclose, is what makes losing the press cheap: the
// gate does move underneath requests already in flight, so each of them asks
// holder for itself rather than trusting the admission it came in on. The
// look and the mint are one critical section, so two simultaneous presses
// have exactly one winner.
func (s *setupServer) start(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TokenHash != nil {
		notFound(w) // claimed already; nothing here announces itself
		return
	}
	// The token exists in the clear only here: it leaves in the cookie and
	// nowhere else - never a log, never the page - and only its hash stays.
	token := rand.Text()
	sum := sha256.Sum256([]byte(token))
	s.TokenHash = sum[:]
	s.setTokenCookie(w, token)
	http.Redirect(w, r, s.prefix+"/setup", http.StatusSeeOther)
}

// authenticate admits a request: the token arrives once in the address bar
// and from then on in the cookie - the one the marker's URL carried, or the
// one start handed the browser that claimed the wizard.
func (s *setupServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// tokenOK is false for a nil hash, so an unclaimed wizard falls
		// straight through to authorized without a redirect loop.
		if token := r.URL.Query().Get("t"); tokenOK(token, s.tokenHash()) {
			s.setTokenCookie(w, token)
			// Away from the address bar and the history, so a shoulder or a
			// bookmark does not keep the token.
			http.Redirect(w, r, s.prefix+"/setup", http.StatusSeeOther)
			return
		}
		// An unclaimed wizard is open - the claim page is what stands there
		// instead of the form, and a fresh install has nothing to steal.
		// Everything past the door needs the key itself.
		if s.tokenHash() != nil && !s.holder(r) {
			notFound(w) // nothing here announces itself
			return
		}
		next.ServeHTTP(w, r)
	})
}

func tokenOK(token string, hash []byte) bool {
	sum := sha256.Sum256([]byte(token))
	return token != "" && subtle.ConstantTimeCompare(sum[:], hash) == 1
}

// setTokenCookie gives the browser the token it presents from here on: the
// one it brought in the address bar, or the one start minted for it when it
// claimed the wizard. It reaches no further than the wizard does, so on a NAS
// where the appliance is one path among a dozen the key to its configuration
// is not handed to the other eleven.
func (s *setupServer) setTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: token, Path: cmp.Or(s.prefix, "/"),
		HttpOnly: true, SameSite: http.SameSiteLaxMode,
		// Deliberately not Secure, unlike the UI's cookies: the wizard is
		// reached over plain http on the LAN, because the appliance
		// terminates no TLS and there is no proxy in front of it yet. A
		// Secure cookie would simply never come back.
	})
}

// submit validates the whole form through the real loader and then saves,
// hands the file over as a download, or renders the problems back.
func (s *setupServer) submit(w http.ResponseWriter, r *http.Request) {
	// Admission lets an unclaimed visitor through to be shown the claim page;
	// it must not let them past it. Everything this handler can do - write the
	// configuration file, hand it back - belongs to whoever pressed Start.
	if !s.holder(r) {
		notFound(w)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, setupFormLimit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "the submitted form is malformed or too large", http.StatusBadRequest)
		return
	}
	values, file := s.values(r.PostForm)
	action := r.PostForm.Get("action")
	var generated string
	var cfg *config.Config
	var err error
	if action == "generate-smtp-password" {
		anonymous, _ := strconv.ParseBool(config.Layer(values, s.Getenv)("S2G_SMTP_ALLOW_ANONYMOUS"))
		switch {
		case s.Getenv("S2G_SMTP_PASSWORD") != "":
			err = errors.New("S2G_SMTP_PASSWORD: cannot generate while S2G_SMTP_PASSWORD is set in the environment; remove the override first")
		case anonymous:
			err = errors.New("S2G_SMTP_ALLOW_ANONYMOUS: turn off anonymous SMTP before generating a password")
		default:
			generated = rand.Text()
			values["S2G_SMTP_PASSWORD"] = generated
		}
	} else {
		cfg, err = config.Load(config.Layer(values, s.Getenv))
	}

	// The real loader through the real precedence, so the wizard cannot
	// disagree with the next start about what is valid.
	general, byField := attribute(err)
	var checks []checkResult
	if action != "generate-smtp-password" && len(general) == 0 && len(byField) == 0 {
		switch {
		case action == "test":
			// Advice, not validation: this renders the form straight back,
			// values and all, so a failing check is one the operator can read
			// and then save anyway.
			checks = runChecks(r.Context(), cfg)
		case action == "download" || s.Path == "":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="`+setupFileName+`"`)
			_, _ = w.Write(s.serialize(values))
			return
		default:
			if err := s.save(values); err == nil {
				p := page{Title: "Saved", Base: s.prefix + "/"}
				if s.OnSaved != nil {
					p.Title = "Starting scan2graph"
					p.InlineCSS = setupStartingStyle(w)
				}
				render(slog.Default(), w, setupTmpl, setupView{
					page: p, Saved: s.Path,
					Steps: s.entraSteps(values), StartAfterSave: s.OnSaved != nil, PublicBaseURL: cfg.PublicBaseURL,
				})
				if s.OnSaved != nil {
					s.OnSaved()
				}
				return
			} else {
				slog.Default().Error("setup: writing the configuration file failed", "path", s.Path, "err", err)
				general = []string{"Writing " + s.Path + " failed: " + err.Error()}
			}
		}
	}
	v := s.view(values, general, byField)
	v.Checks = checks
	v.GeneratedSMTPPassword = generated
	// Everything that reaches this render was handed back rather than saved,
	// so the next press from the page it renders folds into it: the secret a
	// check was just run against, and the one a validation failure would
	// otherwise have cost the operator too.
	s.remember(v.Form, values, file)
	render(slog.Default(), w, setupTmpl, v)
}

// The wizard's listener may be gone before the browser asks for CSS. Include
// only our embedded stylesheet, authorizing its exact bytes on this response.
func setupStartingStyle(w http.ResponseWriter) template.CSS {
	css, err := assets.ReadFile("static/style.css")
	if err != nil {
		panic(err) // embedded at build time, like the templates
	}
	hash := sha256.Sum256(css)
	w.Header().Set("Content-Security-Policy", strings.Replace(contentSecurityPolicy,
		"style-src 'self'", "style-src 'self' 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'", 1))
	return template.CSS(css) // trusted build asset, never configuration or user input
}

// values folds a submission into what the page it came from is showing. An
// absent or empty field removes the setting, so the form can turn something
// off - except a secret, which the page cannot show, so a blank box keeps it.
// A nil form changes nothing.
func (s *setupServer) values(form url.Values) (map[string]string, uint64) {
	base, file := s.base(form.Get("form"))
	values := maps.Clone(base)
	if values == nil {
		values = make(map[string]string, len(setupFields))
	}
	if form == nil {
		return values, file
	}
	for _, f := range setupFields {
		// A newline would end the KEY=value line.
		v := strings.TrimSpace(strings.NewReplacer("\r", "", "\n", " ").Replace(form.Get(f.Name)))
		switch {
		case v != "":
			values[f.Name] = v
		case f.Kind == fieldSecret:
		default:
			// An unchecked checkbox arrives as nothing at all, and unset is
			// what it means: the loader's default, not a written false.
			delete(values, f.Name)
		}
	}
	return values, file
}

// save writes the configuration file and republishes what the wizard reads
// back, under one lock across both. The file is then what this submission
// made it, which a second save with the secret box blank - the page invites
// exactly that - needs, or it would fold into the file as it stood at
// start-up and write the *old* secret back, saying "Saved" all the same.
// Holding the lock across the write is what keeps the two in step: two
// overlapping saves could otherwise land on disk in one order and in memory
// in the other, and a later blank box would restore the loser's value over
// the winner's.
func (s *setupServer) save(values map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFile(s.Path, s.serialize(values)); err != nil {
		return err
	}
	s.FileValues, s.pending, s.file = values, nil, s.file+1 // the file is the answer again, for every page
	return nil
}

// base is what a submission folds into: what the page it names handed back,
// or the file as it stands - which is what a form rendered by a plain GET
// /setup gets, naming an id nothing is remembered under, and what every page
// gets once a save has cleared them. It and tokenHash are the rest of the
// locking: every map here is replaced wholesale rather than written into -
// values clones one before folding into it - so a reader takes the mutex once
// and leaves with a whole map rather than half of two.
func (s *setupServer) base(id string) (map[string]string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Asked here rather than when it was stored, because a save can land
	// between the two: what matters is whether the fold is still current when
	// something folds into it, not whether it was current when it was taken.
	if i := slices.IndexFunc(s.pending, func(p pendingForm) bool { return p.id == id }); i >= 0 && s.pending[i].file == s.file {
		return s.pending[i].values, s.file
	}
	return s.FileValues, s.file
}

// remember keeps the submission a render handed back, under the id of the
// form it hands back with it, because the page cannot show a secret: the next
// press from that page arrives with an empty box, which values() reads as
// "keep what is configured". Without this that means the file, so a green
// "Test the connection" followed by Save writes the expired secret back over
// the one the operator just tested - and says "Saved". It is keyed by the
// form because what an empty box keeps is what was typed into the page the
// operator pressed Save on, and nothing else tells the wizard which page that
// was: with a single slot for all of them, a second tab - or a slow check
// answering after a quick one - decides the secret of a page it never
// rendered.
//
// The id says which page; the file generation says whether the page is still
// talking about the current file. Both are needed and they are different
// questions: a save landing while a check is still running leaves that
// check's page carrying an answer to a file that no longer exists, and no
// amount of knowing which page it came from makes it current again. base
// asks that second question, at the moment something folds into the values,
// because that is the only moment when the answer cannot go stale afterwards.
func (s *setupServer) remember(id string, values map[string]string, file uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending = append(s.pending, pendingForm{id, values, file})
	s.pending = s.pending[max(0, len(s.pending)-setupFormsKept):]
}

func (s *setupServer) tokenHash() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TokenHash
}

// attribute splits a Load failure into messages for individual fields and the
// rest. A line naming exactly one setting the form asks for is shown under
// that box; anything naming several, or none, goes above the form where the
// whole picture is visible. The name stays in the line - view swaps it for
// the field's label, which reads as a sentence where deleting it outright
// left "is required because ..." with no subject. A line can carry the
// submitted value itself - the loader's typed checks quote it, as in
// `invalid duration %q` - so these strings are safe to render, where
// html/template escapes them and only the holder is looking, and never safe
// to log.
func attribute(err error) (general []string, byField map[string]string) {
	if err == nil {
		return nil, nil
	}
	byField = make(map[string]string)
	for _, line := range strings.Split(err.Error(), "\n") {
		if line == "" {
			continue
		}
		name := leadingSetting(line)
		if i := slices.IndexFunc(setupFields, func(f setupField) bool { return f.Name == name }); i >= 0 && byField[name] == "" {
			byField[name] = line
			continue
		}
		general = append(general, line)
	}
	return general, byField
}

// leadingSetting is the setting a loader message is about: every one it
// composes opens with the name, followed by ":", " " or "=". Searching the
// whole line instead would let a submitted value decide where its own error
// appears - typing "S2G_HTTP_ADDR" into another box is enough to make the
// line look like it names two settings - and a message naming several
// genuinely does start with something else, so it lands above the form where
// the whole picture is.
func leadingSetting(line string) string {
	end := strings.IndexFunc(line, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
	})
	if end >= 0 {
		line = line[:end]
	}
	return line
}

// serialize renders the settings as a sorted KEY=value file: a diff between
// two saves stays easy to read.
//
// It also carries what still has to be done in the portal, because Download
// answers with the file and nothing else - no page comes back, so the form
// left on screen is the one rendered before any of this was typed. That is
// the read-only-container workflow, where the file is the only thing that
// travels, so the file is where the reminder has to be. A save gets it too,
// and an operator who comes back to the file months later reads it there.
func (s *setupServer) serialize(values map[string]string) []byte {
	var b strings.Builder
	b.WriteString("# scan2graph configuration, written by the setup wizard.\n" +
		"# Editing it by hand is fine; real environment variables still win.\n")
	if uri := s.redirectURI(values); uri != "" {
		b.WriteString("#\n# The Entra app registration needs this redirect URI, under\n" +
			"# Authentication as a Web platform, or signing in fails:\n#   " + uri + "\n")
	}
	if config.Layer(values, s.Getenv)("S2G_GRAPH_SENDER") != "" {
		b.WriteString("#\n# It also needs the Mail.Send application permission, with admin\n" +
			"# consent granted, or nothing can be mailed out - and Mail.ReadWrite\n" +
			"# beside it if a scan can be larger than 2.2 MB, which the default\n" +
			"# 32 MiB message limit leaves plenty of room for.\n")
	}
	b.WriteString("\n")
	for _, name := range slices.Sorted(maps.Keys(values)) {
		fmt.Fprintf(&b, "%s=%s\n", name, quoteValue(values[name]))
	}
	return []byte(b.String())
}

// quoteValue wraps a value in single quotes when a bare KEY=value line would
// not read back as itself. ParseFile trims the line and strips one matched
// pair of surrounding quotes, so what needs them is a value with an edge
// space, a value that is already wrapped in a matched pair of its own, or one
// containing a "#" - Compose's dotenv reader treats that as the start of an
// inline comment after an unquoted value, where ParseFile would not.
func quoteValue(v string) string {
	wrapped := len(v) >= 2 && (v[0] == '\'' || v[0] == '"') && v[len(v)-1] == v[0]
	if v == strings.TrimSpace(v) && !wrapped && !strings.Contains(v, "#") {
		return v
	}
	return "'" + v + "'"
}

// writeFile replaces path atomically, so a failed write cannot leave the
// appliance with half a configuration file.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+setupFileName+"-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name()) // a no-op once the rename succeeded
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	// On disk before the rename makes it the configuration file: without
	// this, a power loss just after the rename can leave a zero-length file,
	// which the next start reads as a fresh install and answers with an
	// unauthenticated wizard.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// setupView is the page: the fields grouped as the form shows them, plus
// whatever the loader had to say about them.
type setupView struct {
	// Only the response to an explicit generation reveals this value.
	GeneratedSMTPPassword string
	page
	Groups []setupGroup
	Errors []string // not attributable to one field, shown above the form
	// Checks is what "Test the connection" found, shown above the form and
	// only for the submission that asked for it.
	Checks         []checkResult
	Path           string // where Save would write; "" offers only the download
	Saved          string // where it went, on the success page
	StartAfterSave bool
	PublicBaseURL  string // the validated URL, only on the saved page
	// Steps is the walkthrough again, on that same page. The card shows it
	// only to somebody who submits the form and comes back to it: fill
	// everything in, press Save, and this is the last place any of it can
	// still be said. What is missing by then is not visible until the
	// restart, and then only as an AADSTS50011 at sign-in or a Graph refusal
	// on the first scan, neither of which points back here.
	Steps []setupStep
	// Form is this render's id, handed back in a hidden field: it tells one
	// open page from another, gates nothing, and losing it folds into the file.
	Form string
	// Claim replaces the form with the page that offers to claim the wizard,
	// on the fresh install where nobody has yet.
	Claim bool
}

type setupGroup struct {
	Name         string
	Intro        string // one sentence saying what this card is for
	Fields, Rare []setupInput
	// Steps is the app-registration walkthrough, on the Identity card alone.
	Steps []setupStep
	// OpenRare unfolds the disclosure because something inside it was
	// rejected. A complaint is only ever rendered under the box that caused
	// it, so a folded-away one is a dead end: the operator presses Save, the
	// page comes back looking identical, and nothing on it says why.
	OpenRare bool
}

// redirectURI is what the appliance will register with Entra for these
// settings, or "" when it will register nothing because it signs nobody in.
// It answers through the loader's own resolver over the loader's own
// precedence, so it cannot disagree with a real start: the environment sits
// above the file, and a value Load would refuse resolves to nothing here
// rather than being offered with confidence.
func (s *setupServer) redirectURI(values map[string]string) string {
	base := config.ResolveBaseURL(config.Layer(values, s.Getenv))
	if base == "" {
		return ""
	}
	return base + "/auth/callback"
}

// setupStep is one step of the Identity card's walkthrough: what to do in
// the portal, and the value this page worked out for it, if any.
type setupStep struct{ Text, Code string }

// entraSteps is README's "Entra ID app registration" section cut down to the
// steps this configuration actually needs - the one thing the README cannot
// do, because it does not know what the operator has typed. The redirect URI
// is why it exists at all: it is the step people get wrong, and the wizard is
// the only place that already knows the answer.
//
// Which makes being wrong here worse than saying nothing: a URI the appliance
// will not actually register is one the operator pastes into Entra and then
// meets again as AADSTS50011, naming neither this page nor the box that
// caused it. So the answer comes from the loader's own resolver over the
// loader's own precedence rather than from string surgery on the box: the
// environment sits above the file, exactly as a start would, and a value Load
// would refuse resolves to nothing here rather than being printed with
// confidence. A plain GET never runs
// Load, so nothing else on the page would have contradicted it.
func (s *setupServer) entraSteps(values map[string]string) []setupStep {
	getenv := config.Layer(values, s.Getenv)
	steps := []setupStep{{Text: "New registration → a single-tenant app is enough. Its Overview page then shows the Directory (tenant) ID and the Application (client) ID for the two boxes below."}}
	if uri := s.redirectURI(values); uri != "" {
		steps = append(steps, setupStep{
			Text: "Authentication → Add a platform → Web, not SPA: scan2graph holds a client secret and exchanges the code server-side. The redirect URI is exactly:",
			Code: uri,
		})
	} else {
		steps = append(steps, setupStep{Text: "Nothing to add under Authentication yet: the redirect URI is worked out from the Public URL field on this page, so fill that in and come back here for it. An appliance that only mails scans out signs nobody in and needs none at all."})
	}
	steps = append(steps, setupStep{Text: "Certificates & secrets → New client secret. The portal shows its Value once, right after you create it; that is what goes in the Client secret box below."})
	if getenv("S2G_GRAPH_SENDER") != "" {
		steps = append(steps, setupStep{Text: "API permissions → Microsoft Graph → Application permissions → Mail.Send, then Grant admin consent, or nothing can be mailed out. Add Mail.ReadWrite beside it if a scan can be larger than 2.2 MB; the README explains why."})
	}
	return steps
}

// setupInput is one field ready to render. Value is empty for a secret, which
// is never rendered back.
type setupInput struct {
	setupField
	Value   string
	Checked bool
	Error   string
}

// view renders values as the form.
func (s *setupServer) view(values map[string]string, general []string, byField map[string]string) setupView {
	v := setupView{page: page{Title: "Setup", Base: s.prefix + "/"}, Path: s.Path, Errors: general, Form: rand.Text()}
	v.StartAfterSave = s.OnSaved != nil && s.Path != ""
	for _, f := range setupFields {
		in := setupInput{setupField: f, Value: values[f.Name]}
		// The loader names the setting; the operator reads a label. Swapping
		// the first occurrence keeps the sentence whole either way round:
		// "Application (client) ID is required because ..." and "Sending
		// mailbox: ... is not a valid address".
		in.Error = strings.Replace(byField[f.Name], f.Name, f.Label, 1)
		switch f.Kind {
		case fieldSecret:
			// Never rendered back into the page. The hint is what values()
			// does with a blank box on the next press from this page.
			if in.Value != "" {
				in.Placeholder = "configured — leave empty to keep"
			}
			in.Value = ""
		case fieldBool:
			in.Checked, _ = strconv.ParseBool(in.Value)
		}
		if len(v.Groups) == 0 || v.Groups[len(v.Groups)-1].Name != f.Group {
			g := setupGroup{Name: f.Group, Intro: groupIntro[f.Group]}
			if f.Group == groupIdentity {
				g.Steps = s.entraSteps(values)
			}
			v.Groups = append(v.Groups, g)
		}
		g := &v.Groups[len(v.Groups)-1]
		if f.Rare {
			g.Rare = append(g.Rare, in)
			g.OpenRare = g.OpenRare || in.Error != ""
		} else {
			g.Fields = append(g.Fields, in)
		}
	}
	return v
}
