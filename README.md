# 🔍 Smart URL Unshortener, Redirect Tracer & Metadata Inspector API (Go)

![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=for-the-badge&logo=go)
![Security](https://img.shields.io/badge/Security-SSRF%20Protected-critical?style=for-the-badge)
![Memory](https://img.shields.io/badge/Streaming%20Parser-256KB%20Bounded-success?style=for-the-badge)
![Deployment](https://img.shields.io/badge/AWS%20EC2-Production%20Ready-FF9900?style=for-the-badge&logo=amazon-aws)

A fast, security-hardened RESTful Micro-API built with **Go (Golang)** that unshortens URLs, traces complete HTTP redirect chains (`301`, `302`, `307`, `308`), flags suspicious destination links, and extracts **OpenGraph / SEO Metadata** (`title`, `description`, `og:image`, `canonical`) in a single request.

🌐 **Live Production Health Check:** `[https://link-api.aklein.tech/health](https://link-api.aklein.tech/health)`  
🚀 **RapidAPI Marketplace:** `Smart URL Unshortener Redirect Tracer and Metadata Scraper`

---

## ✨ Key Engineering & Security Highlights

* **Custom HTTP Redirect Interceptor (`http.Client.CheckRedirect`):** Captures every intermediate hop, status code, and URL transformation up to 10 hops deep without losing tracking context.
* **Built-in SSRF Protection (Server-Side Request Forgery Guard):** Resolves and validates destination DNS IP addresses at **every redirect hop**, blocking access to loopback (`127.0.0.1`), private networks (`10.x`, `192.168.x`), and cloud metadata endpoints (`169.254.169.254`).
* **Bounded-Memory Streaming HTML Tokenizer (`io.LimitReader` & `x/net/html`):** Streams only the first `256 KB` of the target webpage and halts parsing immediately upon encountering the closing `</head>` tag—preventing Out-Of-Memory (OOM) attacks when inspecting large files or media streams.
* **Phishing & Heuristic Risk Detection:** Automatically flags unencrypted (`HTTP`) final destinations, excessive redirect chains (`4+ hops`), and raw IP-based destination hosts.

---

## 📂 Project Architecture

```text
link-inspector-api/
├── .gitignore                        # Git ignore rules for compiled binaries and env files
├── go.mod                            # Go module definition
├── go.sum                            # Cryptographic dependency checksums
├── main.go                           # Application entrypoint, routing & port configuration
└── internal/
    ├── middleware/
    │   └── rapidapi.go               # RapidAPI Proxy Secret authentication middleware
    └── inspector/
        ├── metadata.go               # Bounded-memory streaming HTML & OpenGraph tokenizer
        └── tracer.go                 # Custom HTTP redirect tracer & SSRF security guard
```

---

## 🔌 API Documentation

### 1. Inspect URL, Redirect Chain & Metadata
Traces a URL from start to finish and extracts preview metadata from the final destination.

* **Endpoint:** `GET /v1/inspect`
* **Query Parameter:** `url` *(required, string)*

#### Example Request (via RapidAPI)
```bash
curl --request GET \
  --url 'https://smart-url-unshortener-redirect-tracer-and-metadata-scraper.p.rapidapi.com/v1/inspect?url=http%3A%2F%2Fgithub.com' \
  --header 'x-rapidapi-host: smart-url-unshortener-redirect-tracer-and-metadata-scraper.p.rapidapi.com' \
  --header 'x-rapidapi-key: YOUR_RAPIDAPI_KEY'
```

#### Example Response (`200 OK`)
```json
{
  "original_url": "http://github.com",
  "final_url": "https://github.com/",
  "final_domain": "github.com",
  "is_shortened": true,
  "total_hops": 1,
  "redirect_chain": [
    {
      "step": 1,
      "url": "http://github.com",
      "status_code": 301
    },
    {
      "step": 2,
      "url": "https://github.com/",
      "status_code": 200
    }
  ],
  "is_https": true,
  "content_type": "text/html; charset=utf-8",
  "metadata": {
    "title": "GitHub · Build and ship software on a single, collaborative platform · GitHub",
    "description": "GitHub is where people build software. More than 150 million people use GitHub to discover, fork, and contribute to over 420 million projects.",
    "og_title": "GitHub · Build and ship software on a single, collaborative platform",
    "og_image": "https://github.githubassets.com/assets/home24-5939032587c9.jpg",
    "og_site_name": "GitHub",
    "canonical_url": "https://github.com/"
  },
  "suspicious": false,
  "total_time_ms": 312
}
```

---

### 2. Service Health Check
* **Endpoint:** `GET /health`

#### Example Response (`200 OK`)
```json
{
  "service": "link-inspector-api",
  "status": "healthy",
  "timestamp": "2026-10-22T18:00:00Z"
}
```

---

## 🛠️ Local Development & Production Deployment

### 1. Run Locally
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/link-inspector-api.git
cd link-inspector-api
go run main.go
```

### 2. Cross-Compile Binary for Linux Production (AWS EC2)
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o link-inspector main.go
```

---

## 📜 License
MIT License. Built with Go.