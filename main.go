package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	// Sesuaikan dengan nama module di go.mod kamu!
	"github.com/acil23/link-inspector-api/internal/inspector"
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

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/inspect", inspectHandler)

	port := ":8081"
	fmt.Printf("🔍 Link Inspector API menyala di http://localhost%s\n", port)
	log.Fatal(http.ListenAndServe(port, mux))
}