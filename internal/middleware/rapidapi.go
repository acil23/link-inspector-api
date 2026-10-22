package middleware

import (
	"encoding/json"
	"net/http"
	"os"
)

func RapidAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		expectedSecret := os.Getenv("RAPIDAPI_PROXY_SECRET")
		if expectedSecret == "" {
			next.ServeHTTP(w, r)
			return
		}

		incomingSecret := r.Header.Get("X-RapidAPI-Proxy-Secret")
		if incomingSecret != expectedSecret {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Forbidden: Direct access not allowed. Please use RapidAPI Hub.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}