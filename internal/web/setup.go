package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
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
	// setupFormLimit bounds a submission. The JSON-valued settings are the
	// only large ones and a household's are a few hundred bytes.
	setupFormLimit = 64 << 10
	// setupFileName is what a downloaded configuration file is called, and
	// what the README tells the operator to mount.
	setupFileName = "scan2graph.env"
	setupBrand    = "scan2graph"
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
}

type setupServer struct {
	SetupOptions
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
func NewSetup(opts SetupOptions) http.Handler {
	s := &setupServer{SetupOptions: opts}
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err) // embedded at build time, cannot fail
	}
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", http.RedirectHandler("/setup", http.StatusSeeOther))
	mux.HandleFunc("GET /setup", func(w http.ResponseWriter, r *http.Request) {
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
				page: page{Title: "Setup", Brand: setupBrand}, Claim: true,
			})
			return
		}
		current, _, _ := s.values(nil)
		render(slog.Default(), w, setupTmpl, s.view(current, nil, nil))
	})
	mux.HandleFunc("POST /setup/start", s.start)
	mux.HandleFunc("POST /setup", s.submit)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	return secureHeaders(s.authenticate(mux))
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
	setTokenCookie(w, token)
	http.Redirect(w, r, "/setup", http.StatusSeeOther)
}

// authenticate admits a request: the token arrives once in the address bar
// and from then on in the cookie - the one the marker's URL carried, or the
// one start handed the browser that claimed the wizard.
func (s *setupServer) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// tokenOK is false for a nil hash, so an unclaimed wizard falls
		// straight through to authorized without a redirect loop.
		if token := r.URL.Query().Get("t"); tokenOK(token, s.tokenHash()) {
			setTokenCookie(w, token)
			// Away from the address bar and the history, so a shoulder or a
			// bookmark does not keep the token.
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
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
// claimed the wizard.
func setTokenCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: setupCookie, Value: token, Path: "/",
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
	values, file, pairErr := s.values(r.PostForm)

	// The real loader through the real precedence, so the wizard cannot
	// disagree with the next start about what is valid. The pair editor's own
	// complaint is written like a loader message and joined in front of them,
	// so it lands under its box through the same path and, being first, is the
	// one shown there rather than the loader's account of the half-typed row
	// the fold left behind.
	cfg, err := config.Load(config.Layer(values, s.Getenv))
	general, byField := attribute(errors.Join(pairErr, err))
	var checks []checkResult
	if len(general) == 0 && len(byField) == 0 {
		action := r.PostForm.Get("action")
		switch {
		case action == "test":
			// Advice, not validation: this renders the form straight back,
			// values and all, so a failing check is one the operator can read
			// and then save anyway.
			checks = runChecks(r.Context(), cfg)
		case action == "download" || s.Path == "":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="`+setupFileName+`"`)
			_, _ = w.Write(serialize(values))
			return
		default:
			if err := s.save(values); err == nil {
				render(slog.Default(), w, setupTmpl, setupView{
					page: page{Title: "Saved", Brand: setupBrand}, Saved: s.Path,
				})
				return
			} else {
				slog.Default().Error("setup: writing the configuration file failed", "path", s.Path, "err", err)
				general = []string{"Writing " + s.Path + " failed: " + err.Error()}
			}
		}
	}
	v := s.view(values, general, byField)
	v.Checks = checks
	// Everything that reaches this render was handed back rather than saved,
	// so the next press from the page it renders folds into it: the secret a
	// check was just run against, and the one a validation failure would
	// otherwise have cost the operator too.
	s.remember(v.Form, values, file)
	render(slog.Default(), w, setupTmpl, v)
}

// values folds a submission into what the page it came from is showing. An
// absent or empty field removes the setting and both of its spellings, so the
// form can turn something off - except where that page holds an answer the
// form cannot show, which a blank box keeps instead: a secret, and any
// setting supplied by its S2G_..._FILE spelling. A nil form changes nothing.
// The error is the pair editor's alone, and reads like a loader message so
// that submit can attribute it to its box the same way.
func (s *setupServer) values(form url.Values) (map[string]string, uint64, error) {
	base, file := s.base(form.Get("form"))
	values := maps.Clone(base)
	if values == nil {
		values = make(map[string]string, len(setupFields))
	}
	if form == nil {
		return values, file, nil
	}
	var pairErr error
	for _, f := range setupFields {
		// A newline would end the KEY=value line; the JSON in a textarea does
		// not care where its whitespace is.
		v := strings.TrimSpace(strings.NewReplacer("\r", "", "\n", " ").Replace(form.Get(f.Name)))
		// The pair editor names its boxes for itself, so a submission carrying
		// them is one the editor rendered - and one without them came from the
		// textarea the unparseable-value fallback puts under f.Name instead.
		if f.Kind == fieldPairs && form.Has(pairFrom) {
			v, pairErr = foldPairs(form)
		}
		switch {
		case v != "":
			values[f.Name] = v
			// One setting, two spellings: leaving the _FILE one behind would
			// make the next start refuse over "both are set", from a box the
			// form does not even show.
			delete(values, f.Name+"_FILE")
		case f.Kind == fieldSecret, values[f.Name+"_FILE"] != "":
			// Blank keeps what the file holds, in whichever spelling: a
			// secret is never rendered into the page, and neither is a value
			// that lives in the file S2G_..._FILE points at, so an empty box
			// is all the operator can be shown either way. Deleting on blank
			// here would mean editing any other field silently drops a
			// documented S2G_GRAPH_SENDER_FILE - and with it email, the web
			// UI or OCR - on the next start. Removing one stays a file edit,
			// which is where it was set.
		default:
			// An unchecked checkbox arrives as nothing at all, and unset is
			// what it means: the loader's default, not a written false.
			delete(values, f.Name)
			delete(values, f.Name+"_FILE")
		}
	}
	return values, file, pairErr
}

// pairFrom and pairTo are what the alias editor calls its two columns on the
// wire: one pair of boxes per row, repeated, so the two slices come back
// index-aligned. Deliberately not S2G_ names, which the fold loop iterates,
// and deliberately not numbered, which would need the page to remember how
// many rows it drew.
const pairFrom, pairTo = "alias-from", "alias-to"

// foldPairs composes the editor's rows into the JSON object the loader already
// parses, so nothing downstream knows the form changed. Rows nobody typed into
// - every page ends with two spares - are dropped, and no row at all leaves the
// setting empty, which reads as "delete it" exactly like an empty box. A row
// with one side filled is kept and named instead: dropping it would quietly
// lose an address the operator did type, and keeping it is what puts it back
// in front of them. Marshalling a map is what sorts the keys, so saving the
// same aliases twice writes the same file.
func foldPairs(form url.Values) (string, error) {
	froms, tos := form[pairFrom], form[pairTo]
	aliases := make(map[string]string, len(froms))
	var err error
	for i, from := range froms {
		from = strings.TrimSpace(from)
		var to string
		if i < len(tos) {
			to = strings.TrimSpace(tos[i])
		}
		if from == "" && to == "" {
			continue
		}
		if from == "" || to == "" {
			err = errors.New("S2G_RECIPIENT_ALIASES: an alias needs both addresses, and one row has only one of them")
		}
		aliases[from] = to
	}
	if len(aliases) == 0 {
		return "", nil
	}
	out, _ := json.Marshal(aliases) // a map of strings always marshals
	return string(out), err
}

// pairRows is the stored value as the editor shows it: one row per alias,
// ordered by the address the printer sends to so two renders agree, then two
// blank rows to type the next alias into. Two standing spares rather than an
// "add" button, which as a second submit before the actions row would become
// the form's default - and Enter in any box would then add a row instead of
// saving. The false answer means the value is not an object of addresses at
// all, which no pair editor can show.
func pairRows(v string) ([]setupPair, bool) {
	aliases := map[string]string{}
	if v != "" && json.Unmarshal([]byte(v), &aliases) != nil {
		return nil, false
	}
	rows := make([]setupPair, 0, len(aliases)+2)
	for _, from := range slices.Sorted(maps.Keys(aliases)) {
		rows = append(rows, setupPair{from, aliases[from]})
	}
	return append(rows, setupPair{}, setupPair{}), true
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
	if err := writeFile(s.Path, serialize(values)); err != nil {
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
// the whole picture is. The _FILE spelling answers to its own box.
func leadingSetting(line string) string {
	end := strings.IndexFunc(line, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
	})
	if end >= 0 {
		line = line[:end]
	}
	return strings.TrimSuffix(line, "_FILE")
}

// serialize renders the settings as a sorted KEY=value file: a diff between
// two saves stays easy to read.
func serialize(values map[string]string) []byte {
	var b strings.Builder
	b.WriteString("# scan2graph configuration, written by the setup wizard.\n" +
		"# Editing it by hand is fine; real environment variables still win.\n\n")
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
	page
	Groups []setupGroup
	Errors []string // not attributable to one field, shown above the form
	// Checks is what "Test the connection" found, shown above the form and
	// only for the submission that asked for it.
	Checks []checkResult
	Path   string // where Save would write; "" offers only the download
	Saved  string // where it went, on the success page
	// Form is this render's id, handed back in a hidden field: it tells one
	// open page from another, gates nothing, and losing it folds into the file.
	Form string
	// Claim replaces the form with the page that offers to claim the wizard,
	// on the fresh install where nobody has yet.
	Claim bool
}

type setupGroup struct {
	Name         string
	Fields, Rare []setupInput
	// OpenRare unfolds the disclosure because something inside it was
	// rejected. A complaint is only ever rendered under the box that caused
	// it, so a folded-away one is a dead end: the operator presses Save, the
	// page comes back looking identical, and nothing on it says why.
	OpenRare bool
}

// setupInput is one field ready to render. Value is empty for a secret, which
// is never rendered back.
type setupInput struct {
	setupField
	Value   string
	Checked bool
	Set     bool // a value is configured that no box can show
	Error   string
	Pairs   []setupPair // fieldPairs only
}

// setupPair is one row of the alias editor: the address the printer sends to,
// and the real address it stands for.
type setupPair struct{ From, To string }

func (s *setupServer) view(values map[string]string, general []string, byField map[string]string) setupView {
	v := setupView{page: page{Title: "Setup", Brand: setupBrand}, Path: s.Path, Errors: general, Form: rand.Text()}
	for _, f := range setupFields {
		in := setupInput{setupField: f, Value: values[f.Name]}
		// The loader names the setting; the operator reads a label. Swapping
		// the first occurrence keeps the sentence whole either way round:
		// "Application (client) ID is required because ..." and "Sending
		// mailbox: ... is not a valid address".
		in.Error = strings.Replace(byField[f.Name], f.Name, f.Label, 1)
		// Set drives the hint that says an empty box keeps what is there, so
		// it has to mean exactly what values() will do with a blank box on
		// the next press from this page - which folds into these values,
		// remember having stored them under the id being rendered.
		in.Set = values[f.Name+"_FILE"] != "" || (f.Kind == fieldSecret && values[f.Name] != "")
		// Set wins over the field's own shape example: once there is a value
		// no box can show, saying so is more important than what one would
		// look like.
		if in.Set {
			in.Placeholder = "configured — leave empty to keep"
		}
		switch f.Kind {
		case fieldSecret:
			// Never rendered back into the page.
			in.Value = ""
		case fieldBool:
			in.Checked, _ = strconv.ParseBool(in.Value)
		case fieldChoice:
			// A value the options cannot show - S2G_LOG_LEVEL=warning, which
			// the loader accepts - would render as "(default)", and the next
			// save would delete a setting nobody touched. Offer it as an
			// option of its own instead.
			if in.Value != "" && !slices.Contains(f.Choice, in.Value) {
				in.Choice = append(slices.Clone(f.Choice), in.Value)
			}
		case fieldPairs:
			// Rows, unless the file holds something that is not an object of
			// addresses at all: somebody hand-edited it, and the wizard is
			// the tool they would reach for to fix it, so show them the text
			// itself in a textarea rather than empty rows that would silently
			// replace it on the next save.
			if rows, ok := pairRows(in.Value); ok {
				in.Pairs = rows
			} else {
				in.Kind = fieldArea
			}
		}
		if len(v.Groups) == 0 || v.Groups[len(v.Groups)-1].Name != f.Group {
			v.Groups = append(v.Groups, setupGroup{Name: f.Group})
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
