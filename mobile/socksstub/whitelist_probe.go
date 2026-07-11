package socksstub

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	defaultWhitelistProbeTimeout = 4 * time.Second
	defaultWhitelistProbePort    = 443
)

type whitelistProbeCycleRequest struct {
	Foreign        []string `json:"foreign"`
	Domestic       []string `json:"domestic"`
	TimeoutMs      int      `json:"timeout_ms"`
	Port           int      `json:"port"`
	InterfaceIndex int      `json:"interface_index"`
}

type whitelistProbeTargetResult struct {
	Group         string `json:"group"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	TCPOK         bool   `json:"tcp_ok"`
	TLSOK         bool   `json:"tls_ok"`
	Pass          bool   `json:"pass"`
	ErrorClass    string `json:"error_class,omitempty"`
	Error         string `json:"error,omitempty"`
	RemoteAddress string `json:"remote_address,omitempty"`
	DurationMs    int64  `json:"duration_ms"`
}

type whitelistProbeCycleResult struct {
	OK             bool                         `json:"ok"`
	Classification string                       `json:"classification"`
	Summary        string                       `json:"summary"`
	DomesticPass   int                          `json:"domestic_pass"`
	DomesticTotal  int                          `json:"domestic_total"`
	ForeignPass    int                          `json:"foreign_pass"`
	ForeignTotal   int                          `json:"foreign_total"`
	Targets        []whitelistProbeTargetResult `json:"targets"`
	Error          string                       `json:"error,omitempty"`
}

// RunWhitelistProbeCycleJSON runs the whitelist detector's carrier probe cycle.
// It is exported through gomobile as SocksstubRunWhitelistProbeCycleJSON.
//
// The decision is comparative: domestic allowlisted targets must pass TCP+TLS,
// while foreign control targets must fail TCP/TLS across independent hosts before
// the app declares default-deny allowlist mode. ICMP is intentionally not used as
// a deciding signal.
func RunWhitelistProbeCycleJSON(configJSON string) string {
	cfg, err := parseWhitelistProbeCycleRequest(configJSON)
	if err != nil {
		return marshalWhitelistProbeResult(whitelistProbeCycleResult{
			OK:             false,
			Classification: "error",
			Summary:        "bad probe config",
			Error:          err.Error(),
		})
	}
	res := runWhitelistProbeCycle(cfg, runTCPThenTLSProbe)
	return marshalWhitelistProbeResult(res)
}

func parseWhitelistProbeCycleRequest(configJSON string) (whitelistProbeCycleRequest, error) {
	cfg := whitelistProbeCycleRequest{}
	if strings.TrimSpace(configJSON) != "" {
		if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
			return cfg, err
		}
	}
	cfg.Foreign = normalizeWhitelistProbeHosts(cfg.Foreign)
	cfg.Domestic = normalizeWhitelistProbeHosts(cfg.Domestic)
	if len(cfg.Foreign) == 0 {
		cfg.Foreign = []string{"google.com", "cloudflare.com"}
	}
	if len(cfg.Domestic) == 0 {
		cfg.Domestic = []string{"ya.ru", "ozon.ru", "gosuslugi.ru"}
	}
	if cfg.TimeoutMs <= 0 || cfg.TimeoutMs > 15000 {
		cfg.TimeoutMs = int(defaultWhitelistProbeTimeout / time.Millisecond)
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		cfg.Port = defaultWhitelistProbePort
	}
	return cfg, nil
}

func normalizeWhitelistProbeHosts(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, h := range in {
		for _, part := range strings.FieldsFunc(h, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '\t' }) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			key := strings.ToLower(part)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, part)
		}
	}
	return out
}

type whitelistProbeFunc func(context.Context, string, int, int) whitelistProbeTargetResult

func runWhitelistProbeCycle(cfg whitelistProbeCycleRequest, probe whitelistProbeFunc) whitelistProbeCycleResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cfg.TimeoutMs+750)*time.Millisecond)
	defer cancel()

	results := make([]whitelistProbeTargetResult, 0, len(cfg.Foreign)+len(cfg.Domestic))
	var mu sync.Mutex
	var wg sync.WaitGroup
	runGroup := func(group string, hosts []string) {
		for _, host := range hosts {
			host := host
			wg.Add(1)
			go func() {
				defer wg.Done()
				r := probe(ctx, host, cfg.Port, cfg.InterfaceIndex)
				r.Group = group
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}()
		}
	}
	runGroup("foreign", cfg.Foreign)
	runGroup("domestic", cfg.Domestic)
	wg.Wait()

	res := whitelistProbeCycleResult{
		OK:            true,
		DomesticTotal: len(cfg.Domestic),
		ForeignTotal:  len(cfg.Foreign),
		Targets:       results,
	}
	for _, r := range results {
		if r.Group == "domestic" && r.Pass {
			res.DomesticPass++
		}
		if r.Group == "foreign" && r.Pass {
			res.ForeignPass++
		}
	}
	res.Classification, res.Summary = classifyWhitelistProbeCycle(res.DomesticPass, res.DomesticTotal, res.ForeignPass, res.ForeignTotal)
	return res
}

func classifyWhitelistProbeCycle(domesticPass, domesticTotal, foreignPass, foreignTotal int) (string, string) {
	if domesticTotal <= 0 || foreignTotal <= 0 {
		return "error", "missing domestic or foreign targets"
	}
	domesticHigh := float64(domesticPass)/float64(domesticTotal) >= 0.60
	foreignZero := foreignPass == 0 && foreignTotal >= 1
	foreignHigh := float64(foreignPass)/float64(foreignTotal) >= 0.60

	switch {
	case domesticHigh && foreignZero:
		return "allowlist", "domestic targets pass while foreign controls fail"
	case domesticHigh && foreignHigh:
		return "normal", "domestic and foreign targets pass"
	case domesticPass == 0 && foreignPass == 0:
		return "offline", "no usable TCP+TLS path to domestic or foreign targets"
	case domesticHigh:
		return "partial", "some foreign controls pass; not full allowlist"
	default:
		return "anomalous", "domestic targets fail; do not declare allowlist"
	}
}

func runTCPThenTLSProbe(ctx context.Context, host string, port int, ifaceIndex int) whitelistProbeTargetResult {
	start := time.Now()
	res := whitelistProbeTargetResult{Host: host, Port: port}
	addr := net.JoinHostPort(host, intToString(port))
	dialer := &net.Dialer{Timeout: deadlineTimeout(ctx, defaultWhitelistProbeTimeout)}
	applyWhitelistProbeInterface(dialer, ifaceIndex)

	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.ErrorClass, res.Error = classifyProbeError(err)
		return res
	}
	res.TCPOK = true
	res.RemoteAddress = tcpConn.RemoteAddr().String()
	_ = tcpConn.Close()

	plainConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.ErrorClass, res.Error = classifyProbeError(err)
		return res
	}
	defer plainConn.Close()

	tlsConn := tls.Client(plainConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // probe reachability/SNI behavior, not PKI validity
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		res.DurationMs = time.Since(start).Milliseconds()
		res.ErrorClass, res.Error = classifyProbeError(err)
		return res
	}
	res.TLSOK = true
	res.Pass = true
	res.ErrorClass = "ok"
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

func deadlineTimeout(ctx context.Context, fallback time.Duration) time.Duration {
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 {
			return d
		}
		return time.Millisecond
	}
	return fallback
}

func classifyProbeError(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	msg := err.Error()
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(strings.ToLower(msg), "timeout") || strings.Contains(strings.ToLower(msg), "deadline") {
		return "timeout", msg
	}
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "connection refused"):
		return "conn_refused", msg
	case strings.Contains(lower, "connection reset") || strings.Contains(lower, "broken pipe") || strings.Contains(lower, "reset by peer"):
		return "reset", msg
	case strings.Contains(lower, "no such host") || strings.Contains(lower, "dns"):
		return "dns_error", msg
	case strings.Contains(lower, "tls") || strings.Contains(lower, "handshake") || strings.Contains(lower, "protocol"):
		return "tls_error", msg
	default:
		return "network_error", msg
	}
}

func marshalWhitelistProbeResult(res whitelistProbeCycleResult) string {
	b, err := json.Marshal(res)
	if err != nil {
		return `{"ok":false,"classification":"error","summary":"marshal failed"}`
	}
	return string(b)
}

func intToString(v int) string {
	// strconv.Itoa without adding another import to the hot path list above.
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
