package inspector

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Hop struct {
	Step       int    `json:"step"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
}

type TraceResult struct {
	OriginalURL   string       `json:"original_url"`
	FinalURL      string       `json:"final_url"`
	FinalDomain   string       `json:"final_domain"`
	IsShortened   bool         `json:"is_shortened"`
	TotalHops     int          `json:"total_hops"`
	RedirectChain []Hop        `json:"redirect_chain"`
	IsHTTPS       bool         `json:"is_https"`
	ContentType   string       `json:"content_type,omitempty"`
	Metadata      PageMetadata `json:"metadata"`
	Suspicious    bool         `json:"suspicious"`
	RiskReasons   []string     `json:"risk_reasons,omitempty"`
	TotalTimeMs   int64        `json:"total_time_ms"`
}

func isSafeHost(host string) error {
	hostname := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostname = h
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return errors.New("domain tidak ditemukan atau gagal di-resolve DNS")
	}

	for _, ipAddr := range ips {
		ip := ipAddr.IP
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return errors.New("akses ke IP internal/lokal (SSRF) ditolak demi keamanan")
		}
	}
	return nil
}

func Trace(rawURL string) (TraceResult, error) {
	start := time.Now()

	target := strings.TrimSpace(rawURL)
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	parsedURL, err := url.ParseRequestURI(target)
	if err != nil || parsedURL.Host == "" {
		return TraceResult{}, errors.New("format URL tidak valid")
	}

	if err := isSafeHost(parsedURL.Host); err != nil {
		return TraceResult{}, err
	}

	var chain []Hop
	maxRedirects := 10

	client := &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.Response != nil && len(via) > 0 {
				prevReq := via[len(via)-1]
				chain = append(chain, Hop{
					Step:       len(via),
					URL:        prevReq.URL.String(),
					StatusCode: req.Response.StatusCode,
				})
			}

			if err := isSafeHost(req.URL.Host); err != nil {
				return err
			}

			if len(via) >= maxRedirects {
				return errors.New("terlalu banyak lompatan redirect (maksimal 10)")
			}
			return nil
		},
	}

	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return TraceResult{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; LinkGuardBot/1.0; +https://aklein.tech)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return TraceResult{}, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	finalDomain := strings.ToLower(resp.Request.URL.Hostname())

	chain = append(chain, Hop{
		Step:       len(chain) + 1,
		URL:        finalURL,
		StatusCode: resp.StatusCode,
	})

	// Ekstrak Metadata jika halaman tujuan berupa HTML
	contentType := resp.Header.Get("Content-Type")
	var meta PageMetadata
	if strings.Contains(strings.ToLower(contentType), "text/html") {
		meta = extractMetadata(resp.Body)
	}

	// Analisis Risiko Keamanan Link
	var reasons []string
	isHTTPS := resp.Request.URL.Scheme == "https"
	if !isHTTPS {
		reasons = append(reasons, "Final destination does not use HTTPS encryption")
	}
	if len(chain)-1 >= 4 {
		reasons = append(reasons, "Excessive redirect hops detected (4+ redirects)")
	}
	if net.ParseIP(finalDomain) != nil {
		reasons = append(reasons, "Final URL uses a raw IP address instead of a domain name")
	}

	result := TraceResult{
		OriginalURL:   target,
		FinalURL:      finalURL,
		FinalDomain:   finalDomain,
		IsShortened:   len(chain) > 1,
		TotalHops:     len(chain) - 1,
		RedirectChain: chain,
		IsHTTPS:       isHTTPS,
		ContentType:   contentType,
		Metadata:      meta,
		Suspicious:    len(reasons) > 0,
		RiskReasons:   reasons,
		TotalTimeMs:   time.Since(start).Milliseconds(),
	}

	return result, nil
}