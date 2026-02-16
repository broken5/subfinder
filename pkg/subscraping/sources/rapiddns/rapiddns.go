// Package rapiddns is a RapidDNS Scraping Engine in Golang
// Supports both free HTML scraping and paid API access
// API Documentation: https://rapiddns.io/help/api
package rapiddns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/broken5/subfinder/v2/pkg/subscraping"
)

var pagePattern = regexp.MustCompile(`class="page-link" href="/subdomain/[^"]+\?page=(\d+)">`)

// apiResponse represents the RapidDNS API response structure
// Actual response format:
// {"status": "ok", "message": {"total": 15495, "status": "ok", "data": [...]}}
type apiResponse struct {
	Status  string `json:"status"`
	Message struct {
		Total int `json:"total"`
		Data  []struct {
			Type      string `json:"type"`
			Value     string `json:"value"`
			Subdomain string `json:"subdomain"`
			Timestamp string `json:"timestamp"`
		} `json:"data"`
	} `json:"message"`
}

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	apiKeys   []string
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		// If API key is available, use API mode
		if len(s.apiKeys) > 0 {
			s.runAPI(ctx, domain, session, results)
		} else {
			// Fallback to HTML scraping mode
			s.runHTMLScraping(ctx, domain, session, results)
		}
	}()

	return results
}

// runAPI uses the RapidDNS API (requires Pro/Max subscription)
func (s *Source) runAPI(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) {
	page := 1
	pageSize := 5000
	seen := make(map[string]struct{})

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.requests++
		apiURL := fmt.Sprintf("https://rapiddns.io/api/search/%s?page=%d&pagesize=%d", domain, page, pageSize)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		req.Header.Set("X-API-KEY", s.apiKeys[0])
		req.Header.Set("Accept", "application/json")

		resp, err := session.Client.Do(req)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		if resp.StatusCode != http.StatusOK {
			// Handle specific API errors
			var errMsg string
			switch resp.StatusCode {
			case http.StatusUnauthorized:
				errMsg = "invalid or expired API key"
			case http.StatusForbidden:
				errMsg = "insufficient permissions, Pro/Max subscription required"
			case http.StatusTooManyRequests:
				errMsg = "rate limit exceeded"
			default:
				errMsg = fmt.Sprintf("unexpected status code: %d", resp.StatusCode)
			}
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", errMsg)}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response apiResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		session.DiscardHTTPResponse(resp)

		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		if response.Status != "ok" {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("API returned status: %s", response.Status)}
			s.errors++
			return
		}

		// Process results
		for _, record := range response.Message.Data {
			subdomain := record.Subdomain
			if subdomain == "" {
				continue
			}

			// Deduplicate
			if _, exists := seen[subdomain]; exists {
				continue
			}
			seen[subdomain] = struct{}{}

			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				s.results++
			}
		}

		// Check if there are more pages
		if len(response.Message.Data) < pageSize || page*pageSize >= response.Message.Total {
			break
		}
		page++
	}
}

// runHTMLScraping uses the free HTML scraping method (no API key required)
func (s *Source) runHTMLScraping(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) {
	page := 1
	maxPages := 1

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.requests++
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://rapiddns.io/subdomain/%s?page=%d&full=1", domain, page))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		session.DiscardHTTPResponse(resp)

		src := string(body)
		for _, subdomain := range session.Extractor.Extract(src) {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				s.results++
			}
		}

		if maxPages == 1 {
			matches := pagePattern.FindAllStringSubmatch(src, -1)
			if len(matches) > 0 {
				lastMatch := matches[len(matches)-1]
				if len(lastMatch) > 1 {
					maxPages, _ = strconv.Atoi(lastMatch[1])
				}
			}
		}

		if page >= maxPages {
			break
		}
		page++
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "rapiddns"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.OptionalKey
}

func (s *Source) NeedsKey() bool {
	return s.KeyRequirement() == subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Requests:  s.requests,
	}
}
