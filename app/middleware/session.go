// Package middleware provides HTTP middleware for the platform.
//
// The session middleware performs two functions:
//  1. RequireSession — a hard gate that returns 401/403 if no valid session
//     is present. Use this on protected routes.
//  2. LoadSession — a soft loader that attaches session+user to the context
//     if a valid cookie is present but does NOT block unauthenticated requests.
//     Use this on public routes that want to show user-aware UI.
package middleware

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/AmanTahiliani/FHIR-Sandbox/app/db"
	"github.com/AmanTahiliani/FHIR-Sandbox/app/models"
)

const sessionCookieName = "session_id"

// SessionMiddleware holds the dependencies needed by the session middleware.
type SessionMiddleware struct {
	store *db.Store
}

// NewSessionMiddleware creates a new SessionMiddleware using the given store.
func NewSessionMiddleware(store *db.Store) *SessionMiddleware {
	return &SessionMiddleware{store: store}
}

// LoadSession is a non-blocking middleware that attempts to resolve a session
// from the request cookie and, if valid, attaches both the Session and User
// to the request context.
//
// Requests without a valid session continue normally — this middleware does
// NOT reject unauthenticated requests. Use RequireSession for protected routes.
func (m *SessionMiddleware) LoadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			// No cookie — proceed without a session context.
			next.ServeHTTP(w, r)
			return
		}

		sess, user, err := m.resolveSession(cookie.Value)
		if err != nil {
			// Invalid or expired session — clear the stale cookie and continue.
			clearSessionCookie(w)
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), models.SessionContextKey{}, sess)
		ctx = context.WithValue(ctx, models.UserContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireSession is a hard-gate middleware. It resolves the session cookie and,
// if valid, attaches session+user to the context. If the session is missing or
// invalid, it returns a 401 Unauthorized response (or redirects to "/" for
// browser clients).
func (m *SessionMiddleware) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			m.handleUnauthorized(w, r)
			return
		}

		sess, user, err := m.resolveSession(cookie.Value)
		if err != nil {
			clearSessionCookie(w)
			m.handleUnauthorized(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), models.SessionContextKey{}, sess)
		ctx = context.WithValue(ctx, models.UserContextKey{}, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveSession looks up the session by token, validates its expiry,
// and fetches the associated user record. Returns both or an error.
func (m *SessionMiddleware) resolveSession(token string) (*models.Session, *models.User, error) {
	sess, err := m.store.GetSession(token)
	if err == sql.ErrNoRows {
		return nil, nil, err
	}
	if err != nil {
		log.Printf("middleware: session lookup error: %v", err)
		return nil, nil, err
	}

	// Ensure we compare in UTC and handle potential timezone interpretation issues
	// from the database driver by forcing both to UTC.
	now := time.Now().UTC()
	expiresAt := sess.ExpiresAt.UTC()

	if now.After(expiresAt) {
		log.Printf("middleware: session %s expired (now=%v, expires=%v)", sess.ID, now, expiresAt)
		// Session has expired — clean it up asynchronously.
		go func() {
			if delErr := m.store.DeleteSession(sess.ID); delErr != nil {
				log.Printf("middleware: failed to delete expired session %s: %v", sess.ID, delErr)
			}
		}()
		return nil, nil, fmt.Errorf("session expired")
	}

	user, err := m.store.GetUserByID(sess.UserID)
	if err != nil {
		log.Printf("middleware: user lookup for session %s failed: %v", sess.ID, err)
		return nil, nil, err
	}

	return sess, user, nil
}

// handleUnauthorized returns a 401 for API/JSON requests and a redirect to
// the root for browser requests.
func (m *SessionMiddleware) handleUnauthorized(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Accept") == "application/json" ||
		r.Header.Get("Content-Type") == "application/json" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// clearSessionCookie sends a Set-Cookie header that immediately expires
// the session cookie in the browser.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// SessionFromContext retrieves the Session from a request context.
// Returns nil if no session has been loaded.
func SessionFromContext(ctx context.Context) *models.Session {
	sess, _ := ctx.Value(models.SessionContextKey{}).(*models.Session)
	return sess
}

// UserFromContext retrieves the User from a request context.
// Returns nil if no user has been loaded.
func UserFromContext(ctx context.Context) *models.User {
	user, _ := ctx.Value(models.UserContextKey{}).(*models.User)
	return user
}
