package inspector

import (
	"io"
	"strings"

	"golang.org/x/net/html"
)

// PageMetadata menyimpan informasi pratinjau halaman web (OpenGraph & SEO tags)
type PageMetadata struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	OGTitle     string `json:"og_title,omitempty"`
	OGImage     string `json:"og_image,omitempty"`
	OGSiteName  string `json:"og_site_name,omitempty"`
	Canonical   string `json:"canonical_url,omitempty"`
}

// extractMetadata membaca maksimal 256KB bagian <head> HTML secara streaming
func extractMetadata(body io.Reader) PageMetadata {
	var meta PageMetadata

	// Batasi pembacaan maksimal 256 KB agar server aman dari file berukuran besar
	limitedReader := io.LimitReader(body, 256*1024)
	tokenizer := html.NewTokenizer(limitedReader)

	inTitle := false

	for {
		tokenType := tokenizer.Next()

		switch tokenType {
		case html.ErrorToken:
			// Selesai membaca atau mencapai batas 256 KB
			return meta

		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tagName := strings.ToLower(token.Data)

			if tagName == "title" {
				inTitle = true
			} else if tagName == "meta" {
				var prop, name, content string
				for _, attr := range token.Attr {
					k := strings.ToLower(attr.Key)
					if k == "property" {
						prop = strings.ToLower(strings.TrimSpace(attr.Val))
					} else if k == "name" {
						name = strings.ToLower(strings.TrimSpace(attr.Val))
					} else if k == "content" {
						content = strings.TrimSpace(attr.Val)
					}
				}

				// Ambil data OpenGraph & Description
				switch {
				case prop == "og:title" && meta.OGTitle == "":
					meta.OGTitle = content
				case prop == "og:description" && meta.Description == "":
					meta.Description = content
				case name == "description" && meta.Description == "":
					meta.Description = content
				case prop == "og:image" && meta.OGImage == "":
					meta.OGImage = content
				case prop == "og:site_name" && meta.OGSiteName == "":
					meta.OGSiteName = content
				}
			} else if tagName == "link" {
				var rel, href string
				for _, attr := range token.Attr {
					k := strings.ToLower(attr.Key)
					if k == "rel" {
						rel = strings.ToLower(strings.TrimSpace(attr.Val))
					} else if k == "href" {
						href = strings.TrimSpace(attr.Val)
					}
				}
				if rel == "canonical" && meta.Canonical == "" {
					meta.Canonical = href
				}
			}

		case html.TextToken:
			if inTitle && meta.Title == "" {
				meta.Title = strings.TrimSpace(tokenizer.Token().Data)
				inTitle = false
			}

		case html.EndTagToken:
			token := tokenizer.Token()
			tagName := strings.ToLower(token.Data)
			if tagName == "title" {
				inTitle = false
			}
			// OPTIMASI PENTING: Begitu tag </head> ditutup, langsung hentikan pembacaan!
			// Kita tidak perlu membuang CPU & bandwidth untuk membaca isi <body>.
			if tagName == "head" {
				return meta
			}
		}
	}
}