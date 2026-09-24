// vksnative-e2e drives the APP's own native VKS path (the vendored fork plus
// the socksstub socketstub bridge -- the same code the iOS Network Extension
// runs) and measures whether the tunnel actually carries traffic over time.
//
// Why it exists: every earlier check exercised the tamizdat repo through the
// CLI, or merely compiled the vendored tree. This harness runs the app's
// compiled path end to end against a real server, so a divergence between the
// fork and the repo shows up as data instead of as a diff.
//
// Flow: SetUpstreamMode("vks") -> SetSamizdatConfig(profile blob) ->
// socksstub SOCKS5 listener -> StartVKSNativeUpstream -> N probes through the
// listener, each an HTTP request to a plain endpoint. Exit status is 0 only if
// at least one probe succeeded, so a broken path cannot pass silently.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/anarki/samizdat-ios/mobile/socksstub"
)

func main() {
	var (
		blob     = flag.String("blob", "", "tamizdat:// or samizdat:// profile URI that carries host/port/sni/pbk/shortid")
		keyHex   = flag.String("vks-key", "", "shared VKS key (64 hex) that authenticates the beacon")
		shortID  = flag.String("shortid", "", "user master shortid (16 hex) carried by the beacon")
		specs    = flag.String("vks", "jazz:stub", "ladder spec; the native transport dials the FIRST entry")
		wakeDNS  = flag.String("wake-dns", "77.88.8.8:53", "resolver for the on-demand wake beacon")
		wakeZone = flag.String("wake-zone", "wake.example.com", "beacon zone served by the server's authoritative NS")
		port     = flag.Int("listen", 11095, "loopback SOCKS5 port the stub should listen on")
		probe    = flag.String("probe", "http://api.ipify.org/", "plain-HTTP probe URL (no TLS: the signal is TCP through the tunnel)")
		count    = flag.Int("n", 20, "number of probes")
		gap      = flag.Duration("gap", 5*time.Second, "pause between probes")
		timeout  = flag.Duration("timeout", 25*time.Second, "per-probe timeout")
		logPath  = flag.String("log", "", "optional file to mirror the stub's in-memory log to")
		logTail  = flag.Int("log-tail", 40, "how many trailing stub log lines to print")
	)
	flag.Parse()
	if *blob == "" || *keyHex == "" || *shortID == "" {
		fmt.Fprintln(os.Stderr, "need -blob, -vks-key and -shortid")
		os.Exit(2)
	}

	socksstub.SetUpstreamMode("vks")
	if err := socksstub.SetSamizdatConfig(*blob); err != nil {
		fmt.Fprintln(os.Stderr, "SetSamizdatConfig:", err)
		os.Exit(2)
	}
	if *logPath != "" {
		socksstub.SetLogSink(*logPath)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	if err := socksstub.Start(addr); err != nil {
		fmt.Fprintln(os.Stderr, "stub Start:", err)
		os.Exit(2)
	}
	defer socksstub.Stop()

	status := socksstub.StartVKSNativeUpstream(*specs, *keyHex, *shortID, *wakeDNS, *wakeZone, *port)
	fmt.Printf("mode=%s listener=%s upstream_start=%s\n", socksstub.CurrentUpstreamMode(), addr, status)

	ok, fail := 0, 0
	for i := 0; i < *count; i++ {
		body, err := getViaSOCKS5(addr, *probe, *timeout)
		if err != nil {
			fail++
			if i%5 == 0 || i >= *count-3 {
				fmt.Printf("probe %2d: FAIL %v\n", i, err)
			}
		} else {
			ok++
			fmt.Printf("probe %2d: ok %s\n", i, strings.TrimSpace(body))
		}
		time.Sleep(*gap)
	}

	fmt.Printf("\nRESULT ok=%d fail=%d of %d   stub_status=%s   conns_active=%d conns_total=%d\n",
		ok, fail, *count, socksstub.Status(), socksstub.ConnectionsActive(), socksstub.ConnectionsTotal())

	logs := socksstub.Logs()
	if logs != "" {
		lines := strings.Split(strings.TrimRight(logs, "\n"), "\n")
		if len(lines) > *logTail {
			lines = lines[len(lines)-*logTail:]
		}
		fmt.Println("--- stub log tail ---")
		for _, l := range lines {
			fmt.Println(l)
		}
	}
	if ok == 0 {
		os.Exit(1)
	}
}

// getViaSOCKS5 performs a SOCKS5 CONNECT through proxyAddr and issues one
// plain-HTTP GET, returning the response body. Hand-rolled so the harness
// depends on nothing beyond the standard library.
func getViaSOCKS5(proxyAddr, rawURL string, timeout time.Duration) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("probe url without host: %q", rawURL)
	}
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "https" {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("bad port %q", portStr)
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Greeting: version 5, one method, "no auth".
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		return "", fmt.Errorf("socks greet read: %w", err)
	}
	if greet[0] != 0x05 || greet[1] != 0x00 {
		return "", fmt.Errorf("socks greet rejected: %v", greet)
	}

	// CONNECT with a domain-name ATYP (the stub resolves, as on device).
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(conn, rep); err != nil {
		return "", fmt.Errorf("socks connect read: %w", err)
	}
	if rep[1] != 0x00 {
		return "", fmt.Errorf("socks connect refused: rep=%d", rep[1])
	}
	if err := skipSocksAddr(conn, rep[3]); err != nil {
		return "", err
	}

	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vksnative-e2e\r\nConnection: close\r\n\r\n", path, u.Host)
	raw, err := io.ReadAll(io.LimitReader(conn, 64*1024))
	if err != nil && len(raw) == 0 {
		return "", err
	}
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return "", fmt.Errorf("no HTTP header terminator in %d bytes", len(raw))
	}
	statusLine := string(raw[:bytes.Index(raw, []byte("\r\n"))])
	if !strings.Contains(statusLine, " 200") && !strings.Contains(statusLine, " 30") {
		return "", fmt.Errorf("bad status line %q", statusLine)
	}
	return string(raw[idx+4:]), nil
}

// skipSocksAddr consumes the BND.ADDR/BND.PORT pair of a SOCKS5 reply.
func skipSocksAddr(conn net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case 0x01: // IPv4
		n = 4
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		n = int(l[0])
	case 0x04: // IPv6
		n = 16
	default:
		return fmt.Errorf("socks reply with unknown atyp %d", atyp)
	}
	buf := make([]byte, n+2)
	_, err := io.ReadFull(conn, buf)
	return err
}
