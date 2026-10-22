package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	// Sesuaikan dengan nama module di go.mod kamu!
	"github.com/acil23/link-inspector-api/internal/inspector"
	"github.com/acil23/link-inspector-api/internal/middleware"
)

func inspectHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Parameter 'url' wajib diisi. Contoh: /v1/inspect?url=https://bit.ly/...",
		})
		return
	}

	result, err := inspector.Trace(targetURL)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{
			"error":      err.Error(),
			"target_url": targetURL,
		})
		return
	}

	json.NewEncoder(w).Encode(result)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"service":   "link-inspector-api",
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("GET /v1/inspect", inspectHandler)

	securedMux := middleware.RapidAPIAuth(mux)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	fmt.Printf("🔍 Link Inspector API menyala di http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, securedMux))
}