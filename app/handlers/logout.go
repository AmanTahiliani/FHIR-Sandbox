// logout.go handles session invalidation and user logout.
package handlers

import (
	"log"
	"net/http"
)

// HandleLogout invalidates the current session and redirects to the home page.
// POST /logout
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil && cookie.Value != "" {
		if delErr := h.store.DeleteSession(cookie.Value); delErr != nil {
			log.Printf("handlers: logout delete session %s: %v", cookie.Value, delErr)
		} else {
			log.Printf("handlers: logged out session %s", cookie.Value)
		}
	}

	// Clear the cookie in the browser regardless of DB outcome.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
