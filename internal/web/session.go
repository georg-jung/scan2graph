package web

import (
	"crypto/rand"
	"sync"
	"time"
)

// sessionTTL is how long one sign-in lasts. A constant rather than a knob:
// nobody running a scanner in their hallway needs to tune this, and the
// sessions are in memory anyway, so a restart signs everyone out regardless.
const sessionTTL = 8 * time.Hour

// session is one signed-in user. It is never mutated after creation, so
// handlers may hold the pointer without further locking.
type session struct {
	identities []string // canonical addresses this user is known by
	name       string   // for the page header only, never for authorization
	expiresAt  time.Time
}

// sessionStore keeps the live sessions in memory. There is no persistence by
// design; see the package doc comment.
type sessionStore struct {
	now func() time.Time

	mu sync.Mutex
	m  map[string]*session
}

// create stores sess under a fresh unguessable id and returns the id. Expired
// sessions are swept here rather than by a goroutine: sign-ins are rare and
// there are only ever a handful of them.
func (s *sessionStore) create(sess *session) string {
	id := rand.Text()
	now := s.now()
	sess.expiresAt = now.Add(sessionTTL)

	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if !now.Before(v.expiresAt) {
			delete(s.m, k)
		}
	}
	s.m[id] = sess
	return id
}

// get returns the session with the given id, or false if there is none or it
// has expired. An expired session is dropped on the spot.
func (s *sessionStore) get(id string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[id]
	if !ok {
		return nil, false
	}
	if !s.now().Before(sess.expiresAt) {
		delete(s.m, id)
		return nil, false
	}
	return sess, true
}

// drop deletes a session server-side, which is what sign-out has to do: a
// cleared cookie alone would leave the id valid for anyone who copied it.
func (s *sessionStore) drop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}
