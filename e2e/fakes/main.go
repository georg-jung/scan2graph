// Command fakes is the local stand-in for Entra, Azure Document Intelligence
// and Microsoft Graph that the end-to-end suite runs the real appliance
// against, plus the /inspect API the suite reads its assertions from.
//
// It shares no code with the appliance on purpose: a fake built out of the
// same helpers as the thing under test proves less. Two listeners, because
// the appliance refuses a plain-HTTP Document Intelligence endpoint and that
// validation is not relaxed for tests - so this process generates a
// self-signed certificate, writes it where SSL_CERT_FILE points, and serves
// Document Intelligence over TLS.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Fixture values, all obviously fake and all in one place: a secret scanner
// has nothing to find and no handler invents a second literal.
const (
	clientID    = "00000000-0000-0000-0000-000000000001"
	sendOnlyID  = "00000000-0000-0000-0000-000000000002"
	userToken   = "fake-user-token" // throwaway, nothing here reads it
	graphSender = "scanner@corp.example"
	graphScope  = "https://graph.microsoft.com/.default"
	diScope     = "https://cognitiveservices.azure.com/.default"
	keyID       = "fake-key"
)

// appRoles is what each app registration was granted, the way Entra reports
// application permissions in an app-only token's "roles" claim - and the only
// difference between the two. The appliance reads Mail.ReadWrite at startup
// to decide whether a scan too large for sendMail goes up in chunks or gets a
// notice, so the suite runs one appliance on each side of that by pointing
// them at different registrations, which is how an operator would see it too.
// Only the first signs users in; the second never gets a redirect URI.
var appRoles = map[string][]string{
	clientID:   {"Mail.Send", "Mail.ReadWrite"},
	sendOnlyID: {"Mail.Send"},
}

// redirectURIs is what this app registration has registered, and authorize
// accepts nothing else: the appliance the harness configures, and the second
// one that e2e/tests/setup.spec.mjs has the setup wizard write a
// configuration file for and then starts on a port of its own.
var redirectURIs = []string{
	"http://127.0.0.1:18080/auth/callback",
	"http://127.0.0.1:18082/auth/callback",
}

// fixtureSecret is the one credential this harness knows, supplied by the
// suite through -secret.
var fixtureSecret string

// Listen addresses. Both the appliance under test (playwright.config.mjs)
// and the suite's fake clients (e2e/lib/fakes.mjs) hardcode these too, so a
// flag to change them would change nothing that reads them.
const (
	httpAddr  = "127.0.0.1:19000" // Entra, Graph and the inspection API
	httpsAddr = "127.0.0.1:19443" // Document Intelligence (TLS)
)

// user is one account the sign-in picker offers.
type user struct{ subject, email, name string }

var users = map[string]user{
	"alice": {"alice-subject", "alice@corp.example", "Alice Adams"},
	"bob":   {"bob-subject", "bob@corp.example", "Bob Brown"},
}

// submission is one analyze request, as /inspect/di reports it.
type submission struct {
	SHA256 string `json:"sha256"`
	Size   int    `json:"size"`
}

// analysis is one accepted analyze operation: which document it came from,
// and how often it has been polled (the first poll answers "running").
type analysis struct {
	sha   string
	polls int
}

// fakes is the whole server: two listeners' worth of handlers over one lot
// of shared state. The appliance's workers and the suite's inspection reads
// touch that state concurrently, so every field below mu is taken under it.
type fakes struct {
	issuer   string // http://127.0.0.1:19000/idp
	diOrigin string // https://127.0.0.1:19443
	key      *rsa.PrivateKey

	mu       sync.Mutex
	diFail   bool
	subs     []submission
	messages []graphMessage
	analyses map[string]*analysis
	drafts   map[string]*graphMessage // created -> sent, when the scan is too big for sendMail
	uploads  map[string]*upload       // one open attachment upload session each
	pending  map[string]pendingAuth   // authorize -> approve
	codes    map[string]grant         // approve -> token
}

func main() {
	certFile := flag.String("cert-file", "./.tmp/fake-ca.pem", "where to write the certificate the appliance must trust")
	// No default: the suite owns the fixture credential (e2e/lib/fakes.mjs)
	// and hands it to both the appliance and this process, so there is one
	// copy of it in the repository rather than one per language.
	flag.StringVar(&fixtureSecret, "secret", "", "the client secret the appliance authenticates with")
	flag.Parse()
	if fixtureSecret == "" {
		log.Fatal("fakes: -secret is required")
	}

	log.SetFlags(0)
	log.SetPrefix("fakes: ")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	// Before the listeners: the appliance reads this file at startup, and the
	// suite treats a reachable HTTP listener as "the fakes are ready".
	cert, err := writeCert(*certFile, key)
	if err != nil {
		log.Fatalf("write certificate: %v", err)
	}

	f := &fakes{
		issuer:   "http://" + httpAddr + "/idp",
		diOrigin: "https://" + httpsAddr,
		key:      key,
		pending:  map[string]pendingAuth{},
		codes:    map[string]grant{},
	}
	f.clear()

	tlsLn, err := tls.Listen("tcp", httpsAddr, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Fatalf("listen on %s: %v", httpsAddr, err)
	}
	ln, err := net.Listen("tcp", httpAddr)
	if err != nil {
		log.Fatalf("listen on %s: %v", httpAddr, err)
	}
	log.Printf("issuer %s, document intelligence %s, certificate %s", f.issuer, f.diOrigin, *certFile)

	go func() { log.Fatal(http.Serve(tlsLn, logging(f.diRoutes()))) }()
	log.Fatal(http.Serve(ln, logging(f.httpRoutes())))
}

func (f *fakes) httpRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /idp/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /idp/jwks", f.jwks)
	mux.HandleFunc("GET /idp/authorize", f.authorize)
	mux.HandleFunc("GET /idp/approve", f.approve)
	mux.HandleFunc("POST /idp/token", f.token)
	mux.HandleFunc("POST /graph/users/{sender}/sendMail", f.sendMail)
	mux.HandleFunc("POST /graph/users/{sender}/messages", f.createDraft)
	mux.HandleFunc("POST /graph/users/{sender}/messages/{id}/attachments/createUploadSession", f.createUploadSession)
	mux.HandleFunc("POST /graph/users/{sender}/messages/{id}/attachments", f.addAttachment)
	mux.HandleFunc("POST /graph/users/{sender}/messages/{id}/send", f.sendDraft)
	// Not under /graph: an upload session's URL is one Graph hands out on a
	// host of its own, and the appliance must not carry its token there.
	mux.HandleFunc("PUT /upload/{id}", f.uploadChunk)
	mux.HandleFunc("POST /inspect/reset", f.reset)
	mux.HandleFunc("POST /inspect/di/mode", f.setDIMode)
	mux.HandleFunc("GET /inspect/di", f.inspectDI)
	mux.HandleFunc("GET /inspect/graph", f.inspectGraph)
	return mux
}

func (f *fakes) diRoutes() http.Handler {
	const model = "/documentintelligence/documentModels/prebuilt-read"
	mux := http.NewServeMux()
	mux.HandleFunc("GET /documentintelligence/documentModels", f.documentModels)
	mux.HandleFunc("POST "+model+":analyze", f.analyze)
	mux.HandleFunc("GET "+model+"/analyzeResults/{id}", f.analyzeResult)
	mux.HandleFunc("GET "+model+"/analyzeResults/{id}/pdf", f.analyzePDF)
	return mux
}

// logging prints the method and path of every request and nothing else: the
// query string carries sign-in parameters, the bodies carry tokens, secrets
// and scanned documents.
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// clear resets everything a test may have left behind; also the initial
// state, so "fresh process" and "after /inspect/reset" cannot drift apart.
func (f *fakes) clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.diFail = false
	f.subs = []submission{}
	f.messages = []graphMessage{}
	f.analyses = map[string]*analysis{}
	f.drafts = map[string]*graphMessage{}
	f.uploads = map[string]*upload{}
	f.pending = map[string]pendingAuth{}
	f.codes = map[string]grant{}
}

func (f *fakes) reset(w http.ResponseWriter, _ *http.Request) {
	f.clear()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakes) setDIMode(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Mode != "ok" && body.Mode != "fail") {
		http.Error(w, `mode must be "ok" or "fail"`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.diFail = body.Mode == "fail"
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakes) inspectDI(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"submissions": f.subs})
}

func (f *fakes) inspectGraph(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"messages": f.messages})
}

// authorized enforces the app-only bearer token Document Intelligence and
// Graph both require, and that it was issued for that service's own scope.
// A fake that served an unauthenticated request would let the appliance
// stop asking for a token without any test noticing; one that ignored the
// scope would accept a token real Entra never issues, and a wrong
// S2G_*_SCOPE would first be heard about in production. The token is a JWT,
// so the scope is a claim to read rather than a suffix to compare.
func authorized(w http.ResponseWriter, r *http.Request, scope string) bool {
	if appClaims(r)["scope"] == scope {
		return true
	}
	writeAPIError(w, http.StatusUnauthorized, "missing or wrong bearer token")
	return false
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// writeAPIError answers in the {"error":{"message":...}} envelope both Azure
// clients unwrap, so a failure shows up in the appliance's log as a sentence
// rather than a status line.
func writeAPIError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": map[string]string{"code": http.StatusText(code), "message": msg}})
}

// writeCert generates a self-signed certificate for 127.0.0.1, signed by
// key, and writes it, PEM encoded, to path, returning the keypair for the
// TLS listener. It is written to a temporary name in the same directory and
// renamed into place, so the appliance never reads a half-written bundle.
func writeCert(path string, key *rsa.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scan2graph end-to-end fake"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return tls.Certificate{}, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
