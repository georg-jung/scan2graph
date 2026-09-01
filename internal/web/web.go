// Package web is the web UI where a household member picks up their scans,
// behind an Entra (Microsoft Entra ID) sign-in.
//
// Every job and document request re-checks, server-side, that one of the
// signed-in user's canonical identities is among the job's recipients. The
// unguessable ids in the URLs are defence in depth and never the check, and a
// job belonging to somebody else answers exactly like one that never existed.
package web

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/georg-jung/scan2graph/internal/config"
	"github.com/georg-jung/scan2graph/internal/jobs"
)

// providerTimeout bounds every call to the identity provider (discovery, JWKS
// refresh, code exchange), so a hung Entra cannot pin a request goroutine.
const providerTimeout = 15 * time.Second

// contentSecurityPolicy allows exactly what the pages use: the stylesheet.
// Nothing else loads, frames, or receives a form post.
const contentSecurityPolicy = "default-src 'none'; style-src 'self'; " +
	"form-action 'self'; base-uri 'none'; frame-ancestors 'none'"

//go:embed templates static
var assets embed.FS

var (
	listTmpl      = mustParse("list.html")
	detailTmpl    = mustParse("detail.html")
	signedOutTmpl = mustParse("signedout.html")
)

func mustParse(page string) *template.Template {
	return template.Must(template.ParseFS(assets, "templates/layout.html", "templates/"+page))
}

// Options configures a Server.
type Options struct {
	Store  *jobs.Store
	Config *config.Config
	Logger *slog.Logger
	Now    func() time.Time // optional, tests
}

// Server serves the web UI. Build one with New and mount Handler.
type Server struct {
	store    *jobs.Store
	cfg      *config.Config
	log      *slog.Logger
	now      func() time.Time
	client   *http.Client
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	sessions sessionStore
	handler  http.Handler
}

// New performs OIDC discovery against the configured authority, so it can fail
// and it takes a context.
func New(ctx context.Context, opts Options) (*Server, error) {
	s := &Server{
		store:  opts.Store,
		cfg:    opts.Config,
		log:    opts.Logger,
		now:    opts.Now,
		client: &http.Client{Timeout: providerTimeout},
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.sessions = sessionStore{now: s.now, m: make(map[string]*session)}

	// The key set ignores this context's cancellation and keeps only the HTTP
	// client, so a startup context is safe to hand it.
	ctx = oidc.ClientContext(ctx, s.client)
	provider, err := oidc.NewProvider(ctx, s.cfg.AuthorityURL)
	if err != nil {
		return nil, fmt.Errorf("web: oidc discovery at %s: %w", s.cfg.AuthorityURL, err)
	}
	s.oauth = &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  s.cfg.PublicBaseURL + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	s.verifier = provider.VerifierContext(ctx, &oidc.Config{ClientID: s.cfg.ClientID})
	s.handler = secureHeaders(s.routes())
	return s, nil
}

// Handler returns the UI's routes. /healthz and /readyz are not part of it.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() http.Handler {
	static, err := fs.Sub(assets, "static")
	if err != nil {
		panic(err) // embedded at build time, cannot fail
	}
	mux := http.NewServeMux()
	mux.Handle("GET /{$}", s.guard(s.handleList))
	mux.Handle("GET /scan/{jobID}", s.guard(s.handleDetail))
	mux.Handle("GET /scan/{jobID}/{docID}", s.guard(s.handleDownload))
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	return mux
}

// secureHeaders applies to every response, including the 404s and the static
// files, so no page can be framed, cached or sniffed into something else.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		next.ServeHTTP(w, r)
	})
}

// guard is the authentication boundary: a request without a live session is
// sent to sign in and the handler never runs. Authorization for a particular
// scan is a separate, per-request check; see job.
func (s *Server) guard(h func(http.ResponseWriter, *http.Request, *session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.session(r)
		if !ok {
			http.Redirect(w, r, "/auth/login", http.StatusSeeOther)
			return
		}
		h(w, r, sess)
	})
}

// job looks up a job and authorizes the caller for it in one step: the job
// must exist, be unexpired (Store.Get enforces both), be web-capable, and
// have one of the caller's canonical identities among its recipients.
//
// Every failure is reported the same way, so "not yours" is indistinguishable
// from "never existed".
func (s *Server) job(sess *session, jobID string) (jobs.Job, bool) {
	j, ok := s.store.Get(jobID)
	if !ok || !j.Caps.Web {
		return jobs.Job{}, false
	}
	for _, id := range sess.identities {
		if slices.Contains(j.Recipients, id) {
			return j, true
		}
	}
	return jobs.Job{}, false
}

// notFound is the single answer for an unknown, expired, non-web or
// somebody-else's job or document.
func notFound(w http.ResponseWriter) { http.Error(w, "not found", http.StatusNotFound) }

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request, sess *session) {
	found := s.store.ListForUser(sess.identities)
	v := listView{page: s.pageFor("Scans", sess), Scans: make([]scanRow, 0, len(found))}
	for _, j := range found {
		v.Scans = append(v.Scans, s.row(j))
		if j.Status == jobs.StatusPending || j.Status == jobs.StatusProcessing {
			v.Refresh = true
		}
	}
	s.render(w, listTmpl, v)
}

func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request, sess *session) {
	j, ok := s.job(sess, r.PathValue("jobID"))
	if !ok {
		notFound(w)
		return
	}
	row := s.row(j)
	v := detailView{
		page:      s.pageFor(row.Subject, sess),
		Scan:      row,
		Documents: make([]docRow, 0, len(j.Documents)),
	}
	v.Refresh = j.Status == jobs.StatusPending || j.Status == jobs.StatusProcessing
	for _, d := range j.Documents {
		v.Documents = append(v.Documents, docRow{
			Name: d.DisplayName,
			Size: humanBytes(d.Size),
			URL:  "/scan/" + j.ID + "/" + d.ID,
		})
	}
	s.render(w, detailTmpl, v)
}

func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request, sess *session) {
	j, ok := s.job(sess, r.PathValue("jobID"))
	if !ok {
		notFound(w)
		return
	}
	docID := r.PathValue("docID")
	i := slices.IndexFunc(j.Documents, func(d jobs.Document) bool { return d.ID == docID })
	if i < 0 {
		notFound(w)
		return
	}
	d := j.Documents[i]

	// While the pipeline still owns the job, OCR replaces these files: the
	// path in this snapshot may already be gone, and the file that is still
	// there is the pre-OCR original, which we must never hand out. The detail
	// page hides the links until then; this covers a guessed or bookmarked
	// URL. A failed job keeps its downloads - the notice email links to them.
	if j.Status == jobs.StatusPending || j.Status == jobs.StatusProcessing {
		http.Error(w, "the scan is still being processed", http.StatusConflict)
		return
	}

	f, err := os.Open(d.Path)
	if err != nil {
		s.log.Error("web: cannot open document file", "job_id", j.ID, "err", err)
		http.Error(w, "document unavailable", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// DisplayName is sanitized by the job store: no quotes, backslashes,
	// FormatMediaType emits RFC 2231's filename* when the sanitized display
	// name is not plain ASCII, which is the form the standards want and Go's
	// own parser reads back.
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition",
		mime.FormatMediaType("attachment", map[string]string{"filename": d.DisplayName}))
	w.Header().Set("Content-Length", strconv.FormatInt(d.Size, 10))
	_, _ = io.Copy(w, f)
}

// page is what every template's layout needs.
type page struct {
	Title    string
	Brand    string // the operator's S2G_UI_TITLE, rendered escaped
	User     string
	SignedIn bool
	Refresh  bool // set while a scan on the page is still being worked on
}

type listView struct {
	page
	Scans []scanRow
}

type detailView struct {
	page
	Scan      scanRow
	Documents []docRow
}

// scanRow is one job as the templates see it: everything already formatted,
// so the templates stay free of logic.
type scanRow struct {
	ID       string
	Received string
	Profile  string
	Subject  string
	Size     string // "1.2 MB", or "2 files · 3.1 MB" for a rarer multi-document scan
	Status   string
	Expires  string
	Error    string
}

type docRow struct {
	Name string
	Size string
	URL  string
}

// pageFor builds the layout's data for a signed-in page.
func (s *Server) pageFor(title string, sess *session) page {
	return page{Title: title, Brand: s.cfg.UITitle, User: sess.name, SignedIn: true}
}

func (s *Server) row(j jobs.Job) scanRow {
	return scanRow{
		ID:       j.ID,
		Received: j.ReceivedAt.Format("2 Jan 15:04"),
		Profile:  j.Profile,
		Subject:  j.Subject,
		Size:     scanSize(j.Documents),
		Status:   string(j.Status),
		Expires:  expiresIn(j.ExpiresAt.Sub(s.now())),
		Error:    j.Error,
	}
}

func (s *Server) render(w http.ResponseWriter, t *template.Template, data any) {
	// Render first, write second: a template error must not leave half a page
	// behind a 200.
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", data); err != nil {
		s.log.Error("web: rendering page failed", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

func expiresIn(d time.Duration) string {
	m := int(d.Round(time.Minute).Minutes())
	switch {
	case m < 1:
		return "expires any moment"
	case m < 60:
		return fmt.Sprintf("expires in %d min", m)
	default:
		return fmt.Sprintf("expires in %d h %d min", m/60, m%60)
	}
}

// scanSize is what a scan weighs, said the way the 99% case wants to hear it:
// one document is just its size, and only a rarer multi-document scan needs
// to say how many there are.
func scanSize(docs []jobs.Document) string {
	var total int64
	for _, d := range docs {
		total += d.Size
	}
	if len(docs) == 1 {
		return humanBytes(total)
	}
	return fmt.Sprintf("%d files · %s", len(docs), humanBytes(total))
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f kB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
