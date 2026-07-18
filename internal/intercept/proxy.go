package intercept

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ForwardProxy is a local HTTP forward proxy that gates outbound requests through policy.
type ForwardProxy struct {
	evaluate func(ctx context.Context, raw map[string]any) (allowed bool, message string)
	session  sessionMeta
}

type sessionMeta struct {
	id          string
	task        string
	environment string
}

// StartForwardProxy listens on 127.0.0.1:0 and returns the proxy URL and server.
func StartForwardProxy(ctx context.Context, meta sessionMeta, evaluate func(context.Context, map[string]any) (bool, string)) (string, *http.Server, error) {
	proxy := &ForwardProxy{
		evaluate: evaluate,
		session:  meta,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("listen proxy: %w", err)
	}
	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	addr := ln.Addr().String()
	return "http://" + addr, srv, nil
}

func (p *ForwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleCONNECT(w, r)
		return
	}
	p.handleHTTP(w, r)
}

func (p *ForwardProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	body, bodyLen, err := readRequestBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	scheme := r.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	if r.URL.RawQuery != "" {
		path = path + "?" + r.URL.RawQuery
	}

	headers := flattenHeaders(r.Header)
	egressBytes := bodyLen
	if egressBytes == 0 {
		egressBytes = estimateHeaderBytes(r.Header)
	}

	raw := map[string]any{
		"method":       r.Method,
		"host":         host,
		"path":         path,
		"scheme":       scheme,
		"headers":      headers,
		"egress_bytes": egressBytes,
		"session_id":   p.session.id,
		"environment":  p.session.environment,
		"task":         p.session.task,
	}

	allowed, msg := p.evaluate(ctx, raw)
	if !allowed {
		http.Error(w, "AgentGuard blocked: "+msg, http.StatusForbidden)
		return
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, r.URL.String(), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	outReq.Header = r.Header.Clone()
	if r.URL.Scheme == "" || r.URL.Host == "" {
		outReq.URL.Scheme = scheme
		outReq.URL.Host = host
	}

	client := &http.Client{Timeout: 0, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (p *ForwardProxy) handleCONNECT(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	host := r.Host
	if host == "" {
		http.Error(w, "missing CONNECT host", http.StatusBadRequest)
		return
	}

	raw := map[string]any{
		"method":       "CONNECT",
		"host":         host,
		"path":         "",
		"scheme":       "https",
		"connect":      true,
		"egress_bytes": int64(0),
		"session_id":   p.session.id,
		"environment":  p.session.environment,
		"task":         p.session.task,
		"headers":      flattenHeaders(r.Header),
	}

	allowed, msg := p.evaluate(ctx, raw)
	if !allowed {
		http.Error(w, "AgentGuard blocked: "+msg, http.StatusForbidden)
		return
	}

	destConn, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(destConn, clientConn)
	pipe(clientConn, destConn)
}

func pipe(dst net.Conn, src net.Conn) {
	_, _ = io.Copy(dst, src)
}

func readRequestBody(r *http.Request) (io.ReadCloser, int64, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return http.NoBody, 0, nil
	}
	data, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, 0, err
	}
	return io.NopCloser(strings.NewReader(string(data))), int64(len(data)), nil
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, vals := range h {
		out[strings.ToLower(k)] = strings.Join(vals, ", ")
	}
	return out
}

func estimateHeaderBytes(h http.Header) int64 {
	var n int64
	for k, vals := range h {
		for _, v := range vals {
			n += int64(len(k) + len(v) + 4)
		}
	}
	return n
}

func copyHeader(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

// ProxyEnvVars returns HTTP_PROXY/HTTPS_PROXY values for a proxy URL.
func ProxyEnvVars(proxyURL string) (httpProxy, httpsProxy, noProxy string) {
	return proxyURL, proxyURL, "localhost,127.0.0.1"
}

// ReadProxyRequest is a test helper for raw HTTP proxy requests.
func ReadProxyRequest(r io.Reader) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(r))
}
