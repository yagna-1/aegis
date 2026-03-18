package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yagna-1/aegis/internal/audit"
	"github.com/yagna-1/aegis/internal/budget"
	"github.com/yagna-1/aegis/internal/config"
	"github.com/yagna-1/aegis/internal/keychain"
)

type Server struct {
	cfg    *config.Config
	client *http.Client
	allow  map[string]bool
	log    *audit.Logger
	guard  *budget.Guard
}

func New(cfg *config.Config, log *audit.Logger) *Server {
	allow := make(map[string]bool, len(cfg.Allowlist))
	for _, d := range cfg.Allowlist {
		allow[strings.ToLower(d)] = true
	}

	budgets := make(map[string]budget.DomainBudget, len(cfg.Budgets))
	for domain, b := range cfg.Budgets {
		budgets[domain] = budget.DomainBudget{
			MaxRequestsPerHour: b.MaxRequestsPerHour,
			LoopThreshold:      b.LoopThreshold,
		}
	}

	return &Server{
		cfg:   cfg,
		allow: allow,
		log:   log,
		guard: budget.New(budgets),
		client: &http.Client{
			Timeout: 60 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *Server) isAllowed(host string) bool {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if s.allow[host] {
		return true
	}
	for allowed := range s.allow {
		if strings.HasSuffix(host, "."+allowed) {
			return true
		}
	}
	return false
}

func (s *Server) credential(host string) config.Credential {
	if c, ok := s.cfg.Credentials[host]; ok {
		return c
	}
	for domain, c := range s.cfg.Credentials {
		if strings.HasSuffix(host, "."+domain) {
			return c
		}
	}
	return config.Credential{}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		stats := s.guard.Stats()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","service":"aegis","allowlist":%d,"request_counts":{`, len(s.cfg.Allowlist))
		first := true
		for domain, count := range stats {
			if !first {
				fmt.Fprint(w, ",")
			}
			fmt.Fprintf(w, `"%s":%d`, domain, count)
			first = false
		}
		fmt.Fprintln(w, "}}")
		return
	}

	targetRaw := r.Header.Get("X-Aegis-Target")
	if targetRaw == "" {
		http.Error(w, "missing required header: X-Aegis-Target", http.StatusBadRequest)
		return
	}

	targetURL, err := url.Parse(targetRaw)
	if err != nil || targetURL.Host == "" {
		http.Error(w, "invalid X-Aegis-Target URL", http.StatusBadRequest)
		return
	}

	host := targetURL.Hostname()
	entry := audit.NewEntry("proxy", r.Method, targetRaw, host)

	if !s.isAllowed(host) {
		entry.Blocked = true
		entry.BlockedMsg = "domain not in allowlist"
		s.log.Log(entry)
		http.Error(w, fmt.Sprintf("domain %q is not in the allowlist", host), http.StatusForbidden)
		return
	}

	blocked, warning := s.guard.Check(host, r.Method, targetRaw)
	if blocked {
		entry.Blocked = true
		entry.BlockedMsg = warning
		s.log.Log(entry)
		w.Header().Set("X-Aegis-Warning", warning)
		http.Error(w, "rate limit exceeded: "+warning, http.StatusTooManyRequests)
		return
	}
	if warning != "" {
		w.Header().Set("X-Aegis-Warning", warning)
	}

	for k := range r.Header {
		if isAuthHeader(k) {
			entry.Blocked = true
			entry.BlockedMsg = "caller-supplied auth header rejected"
			s.log.Log(entry)
			http.Error(w, "do not set auth headers — Aegis injects credentials automatically", http.StatusBadRequest)
			return
		}
	}

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetRaw, r.Body)
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusInternalServerError)
		return
	}

	for k, vals := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-aegis-") {
			continue
		}
		for _, v := range vals {
			outReq.Header.Add(k, v)
		}
	}

	cred := s.credential(host)
	if cred.Header != "" {
		expanded, err := config.ExpandTemplateStrict(cred.Template, keychain.Get)
		if err != nil {
			entry.Blocked = true
			entry.BlockedMsg = "credential resolution failed: " + err.Error()
			s.log.Log(entry)
			http.Error(w, "credential resolution failed for allowlisted domain", http.StatusBadGateway)
			return
		}
		outReq.Header.Set(cred.Header, expanded)
		entry.CredHeader = cred.Header
	}

	start := time.Now()
	resp, err := s.client.Do(outReq)
	if err != nil {
		entry.BlockedMsg = err.Error()
		s.log.Log(entry)
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	entry.Status = resp.StatusCode
	entry.DurationMS = time.Since(start).Milliseconds()
	s.log.Log(entry)

	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (s *Server) Run(port int) error {
	addr := fmt.Sprintf(":%d", port)
	domains := strings.Join(s.cfg.Allowlist, ", ")
	fmt.Printf("[aegis] proxy listening on http://localhost%s\n", addr)
	fmt.Printf("[aegis] allowlist: %s\n", domains)
	return http.ListenAndServe(addr, s)
}

func isAuthHeader(header string) bool {
	lower := strings.ToLower(strings.TrimSpace(header))
	if lower == "authorization" || lower == "proxy-authorization" ||
		lower == "x-api-key" || lower == "api-key" || lower == "x-auth-token" {
		return true
	}
	return strings.Contains(lower, "api-key") || strings.Contains(lower, "authorization")
}

