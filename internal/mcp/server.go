package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yagna-1/aegis/internal/audit"
	"github.com/yagna-1/aegis/internal/budget"
	"github.com/yagna-1/aegis/internal/config"
	"github.com/yagna-1/aegis/internal/keychain"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type httpRequestArgs struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    string            `json:"body,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

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
		cfg:    cfg,
		allow:  allow,
		log:    log,
		guard:  budget.New(budgets),
		client: &http.Client{Timeout: 60 * time.Second},
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

func (s *Server) Run() {
	fmt.Fprintln(os.Stderr, "[aegis-mcp] ready")
	scanner := bufio.NewScanner(os.Stdin)
	enc := json.NewEncoder(os.Stdout)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		resp := s.dispatch(req)

		if resp.ID != nil || resp.Error != nil || resp.Result != nil {
			enc.Encode(resp)
		}
	}
}

func (s *Server) dispatch(req rpcRequest) rpcResponse {
	switch req.Method {
	case "initialize":
		return rpcResponse{
			JSONRPC: "2.0", ID: req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]string{"name": "aegis", "version": "2.0.0"},
			},
		}
	case "initialized":
		return rpcResponse{}
	case "tools/list":
		return s.toolsList(req)
	case "tools/call":
		return s.toolsCall(req)
	default:
		return rpcResponse{JSONRPC: "2.0", ID: req.ID, Error: &rpcError{Code: -32601, Message: "method not found"}}
	}
}

func (s *Server) toolsList(req rpcRequest) rpcResponse {
	return rpcResponse{
		JSONRPC: "2.0", ID: req.ID,
		Result: map[string]any{
			"tools": []map[string]any{{
				"name": "http_request",
				"description": "Make an authenticated HTTP request to an allowlisted API. " +
					"Aegis injects credentials automatically — do NOT include auth headers. " +
					"Allowed domains: " + strings.Join(s.cfg.Allowlist, ", "),
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"method":  map[string]any{"type": "string", "enum": []string{"GET", "POST", "PUT", "PATCH", "DELETE"}},
						"url":     map[string]any{"type": "string", "description": "Full target URL"},
						"body":    map[string]any{"type": "string", "description": "JSON request body (optional)"},
						"headers": map[string]any{"type": "object", "description": "Non-auth headers (Content-Type etc.)"},
					},
					"required": []string{"method", "url"},
				},
			}},
		},
	}
}

func (s *Server) toolsCall(req rpcRequest) rpcResponse {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, "invalid params")
	}
	if p.Name != "http_request" {
		return errResp(req.ID, "unknown tool: "+p.Name)
	}

	var args httpRequestArgs
	if err := json.Unmarshal(p.Arguments, &args); err != nil {
		return errResp(req.ID, "invalid arguments: "+err.Error())
	}
	if args.URL == "" || args.Method == "" {
		return errResp(req.ID, "method and url are required")
	}

	var bodyReader io.Reader
	if args.Body != "" {
		bodyReader = strings.NewReader(args.Body)
	}

	outReq, err := http.NewRequest(strings.ToUpper(args.Method), args.URL, bodyReader)
	if err != nil {
		return errResp(req.ID, "invalid URL or method: "+err.Error())
	}

	host := outReq.URL.Hostname()
	entry := audit.NewEntry("mcp", args.Method, args.URL, host)

	if !s.isAllowed(host) {
		entry.Blocked = true
		entry.BlockedMsg = "domain not in allowlist"
		s.log.Log(entry)
		return errResp(req.ID, fmt.Sprintf("domain %q not allowed. Allowed: %s", host, strings.Join(s.cfg.Allowlist, ", ")))
	}

	blocked, warning := s.guard.Check(host, args.Method, args.URL)
	if blocked {
		entry.Blocked = true
		entry.BlockedMsg = warning
		s.log.Log(entry)
		return errResp(req.ID, "rate limit: "+warning)
	}

	for k, v := range args.Headers {
		if isAuthHeader(k) {
			return errResp(req.ID, "do not set auth headers — Aegis injects them automatically")
		}
		outReq.Header.Set(k, v)
	}

	cred := s.credential(host)
	if cred.Header != "" {
		resolved, err := config.ExpandTemplateStrict(cred.Template, keychain.Get)
		if err != nil {
			entry.Blocked = true
			entry.BlockedMsg = "credential resolution failed: " + err.Error()
			s.log.Log(entry)
			return errResp(req.ID, "credential resolution failed for allowlisted domain")
		}
		outReq.Header.Set(cred.Header, resolved)
		entry.CredHeader = cred.Header
	}

	fmt.Fprintf(os.Stderr, "[aegis-mcp] %s %s\n", outReq.Method, args.URL)

	start := time.Now()
	resp, err := s.client.Do(outReq)
	if err != nil {
		s.log.Log(entry)
		return errResp(req.ID, "upstream failed: "+err.Error())
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	entry.Status = resp.StatusCode
	entry.DurationMS = time.Since(start).Milliseconds()
	s.log.Log(entry)

	text := fmt.Sprintf("HTTP %d\n", resp.StatusCode)
	if warning != "" {
		text += fmt.Sprintf("X-Aegis-Warning: %s\n", warning)
	}
	text += "\n" + string(body)

	return rpcResponse{
		JSONRPC: "2.0", ID: req.ID,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
		},
	}
}

func errResp(id any, msg string) rpcResponse {
	return rpcResponse{
		JSONRPC: "2.0", ID: id,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": "Error: " + msg}},
			"isError": true,
		},
	}
}

func isAuthHeader(header string) bool {
	lower := strings.ToLower(strings.TrimSpace(header))
	if lower == "authorization" || lower == "proxy-authorization" ||
		lower == "x-api-key" || lower == "api-key" || lower == "x-auth-token" {
		return true
	}
	return strings.Contains(lower, "api-key") || strings.Contains(lower, "authorization")
}

