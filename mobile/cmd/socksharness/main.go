// Command socksharness drives the iOS client's REAL data path on Linux:
// socksstub (the same package the app and the extension link) with the
// native VKS room carrier installed, exactly as PacketTunnelProvider wires
// it. TCP goes through a SOCKS5 CONNECT; UDP goes through hev's custom
// FWD_UDP command (0x05), which is the path DNS/QUIC/APNs take on the phone.
//
// This exists because testing the native transport with the standalone e2e
// client proves nothing about the phone: every failure the operator hit
// (carrier latch, pool cap, stranded flows, probe budgets) lives in
// socksstub, not in the transport.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/anarki/samizdat-ios/mobile/socksstub"
)

func main() {
	var (
		blob      = flag.String("blob", "", "tamizdat:// profile URI")
		shortID   = flag.String("shortid", "", "user master shortid (16 hex)")
		specs     = flag.String("vks", "", "room ladder spec, e.g. telemost:https://...")
		wakeDNS   = flag.String("wake-dns", "77.88.8.8:53", "wake beacon resolver")
		wakeZone  = flag.String("wake-zone", "", "wake beacon zone")
		listen    = flag.Int("listen", 19001, "loopback SOCKS5 port for socksstub")
		n         = flag.Int("n", 5, "probes per lane")
		gap       = flag.Duration("gap", 3*time.Second, "pause between probe rounds")
		timeout   = flag.Duration("timeout", 25*time.Second, "per-probe timeout")
		dnsTarget = flag.String("dns", "8.8.8.8:53", "UDP target for the DNS lane")
		logPath   = flag.String("log", "", "write the socksstub log here")
		hold      = flag.Duration("hold", 0, "after the probes, hold ONE tcp conn idle for this long, then use it")
		holdPing  = flag.Duration("hold-ping", 0, "during -hold, write one byte this often (0 = stay silent)")
		holdDest  = flag.String("hold-dest", "1.1.1.1:80", "destination for the -hold connection")
	)
	flag.Parse()

	if *blob == "" || *shortID == "" || *specs == "" {
		fmt.Fprintln(os.Stderr, "need -blob, -shortid and -vks")
		os.Exit(2)
	}

	if *logPath != "" {
		socksstub.SetLogSink(*logPath)
	}
	if err := socksstub.Start(fmt.Sprintf("127.0.0.1:%d", *listen)); err != nil {
		fmt.Fprintf(os.Stderr, "socksstub start: %v\n", err)
		os.Exit(1)
	}
	defer socksstub.Stop()

	socksstub.SetUpstreamMode("vks")
	if err := socksstub.SetSamizdatConfig(*blob); err != nil {
		fmt.Fprintf(os.Stderr, "SetSamizdatConfig: %v\n", err)
		os.Exit(1)
	}
	st := socksstub.StartVKSNativeUpstream(*specs, *shortID, *wakeDNS, *wakeZone, *listen)
	fmt.Printf("native upstream: %s\n", st)
	if !socksstub.VKSNativeRunning() {
		fmt.Fprintln(os.Stderr, "native carrier did not come up")
		os.Exit(1)
	}

	proxy := fmt.Sprintf("127.0.0.1:%d", *listen)
	okTCP, okUDP := 0, 0

	for i := 0; i < *n; i++ {
		start := time.Now()
		terr := probeTCP(proxy, "api.ipify.org:80", *timeout)
		if terr == nil {
			okTCP++
		}
		fmt.Printf("probe %d tcp: %-52s %6dms\n", i, verdict(terr), time.Since(start).Milliseconds())

		start = time.Now()
		uerr := probeUDP(proxy, *dnsTarget, *timeout)
		if uerr == nil {
			okUDP++
		}
		fmt.Printf("probe %d udp: %-52s %6dms\n", i, verdict(uerr), time.Since(start).Milliseconds())

		if i != *n-1 {
			time.Sleep(*gap)
		}
	}

	// The download case: one conn stays open and quiet for longer than the
	// server's idle timeout. Client->server traffic is then only KCP ACKs,
	// which never reach the application callback, so a room that is released
	// on "no traffic" alone dies mid-transfer.
	if *hold > 0 {
		err := holdConn(proxy, *holdDest, *hold, *holdPing, *timeout)
		fmt.Printf("hold %s: %s\n", *hold, verdict(err))
		if err != nil {
			os.Exit(1)
		}
	}

	fmt.Printf("RESULT tcp ok=%d/%d  udp ok=%d/%d\n", okTCP, *n, okUDP, *n)
	if okTCP == 0 || okUDP == 0 {
		os.Exit(1)
	}
}

func verdict(err error) string {
	if err == nil {
		return "ok"
	}
	return "FAIL " + err.Error()
}

// probeTCP opens a SOCKS5 CONNECT through socksstub and sends one HTTP
// request, requiring a response line back.
func probeTCP(proxy, dest string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	if err := socksHandshake(c); err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	if err := socksRequest(c, 0x01, host, uint16(port)); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return err
	}
	buf := make([]byte, 32)
	if _, err := io.ReadFull(c, buf); err != nil {
		return fmt.Errorf("no response: %w", err)
	}
	return nil
}

// probeUDP opens hev's FWD_UDP stream through socksstub and resolves one DNS
// name, requiring a matching reply id back.
func probeUDP(proxy, target string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", proxy)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	if err := socksHandshake(c); err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return fmt.Errorf("dns target must be an IPv4 literal")
	}
	// FWD_UDP carries a placeholder destination in the request itself.
	if err := socksRequest(c, 0x05, "0.0.0.0", 0); err != nil {
		return err
	}

	// DNS query for example.com, A record.
	q := buildDNSQuery(0x4242)
	// Frame: datlen(2) | hdrlen(1) | atyp(1) | addr(4) | port(2) | data
	hdrLen := 3 + 1 + 4 + 2
	frame := make([]byte, 0, hdrLen+len(q))
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(q)))
	frame = append(frame, byte(hdrLen), 0x01)
	frame = append(frame, ip...)
	frame = binary.BigEndian.AppendUint16(frame, uint16(port))
	frame = append(frame, q...)
	if _, err := c.Write(frame); err != nil {
		return err
	}

	// Reverse frame: same layout, carrying the DNS answer.
	head := make([]byte, 3)
	if _, err := io.ReadFull(c, head); err != nil {
		return fmt.Errorf("no udp reply: %w", err)
	}
	datLen := binary.BigEndian.Uint16(head[0:2])
	addrLen := int(head[2]) - 3
	if addrLen < 0 || addrLen > 64 {
		return fmt.Errorf("bad udp frame hdrlen %d", head[2])
	}
	if _, err := io.ReadFull(c, make([]byte, addrLen)); err != nil {
		return err
	}
	answer := make([]byte, datLen)
	if _, err := io.ReadFull(c, answer); err != nil {
		return err
	}
	if len(answer) < 2 || binary.BigEndian.Uint16(answer[:2]) != 0x4242 {
		return fmt.Errorf("udp reply id mismatch (%d bytes)", len(answer))
	}
	return nil
}

func socksHandshake(c net.Conn) error {
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(c, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks greeting rejected: %v", resp)
	}
	return nil
}

func socksRequest(c net.Conn, cmd byte, host string, port uint16) error {
	ip := net.ParseIP(host).To4()
	req := []byte{0x05, cmd, 0x00}
	if ip != nil {
		req = append(req, 0x01)
		req = append(req, ip...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("host too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return err
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks reply rep=%d", head[1])
	}
	switch head[3] {
	case 0x01:
		_, err := io.ReadFull(c, make([]byte, 4+2))
		return err
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, int(l[0])+2))
		return err
	case 0x04:
		_, err := io.ReadFull(c, make([]byte, 16+2))
		return err
	default:
		return fmt.Errorf("socks reply atyp=%d", head[3])
	}
}

func buildDNSQuery(id uint16) []byte {
	q := make([]byte, 0, 32)
	q = binary.BigEndian.AppendUint16(q, id)
	q = append(q, 0x01, 0x00) // RD
	q = binary.BigEndian.AppendUint16(q, 1)
	q = binary.BigEndian.AppendUint16(q, 0)
	q = binary.BigEndian.AppendUint16(q, 0)
	q = binary.BigEndian.AppendUint16(q, 0)
	for _, label := range []string{"example", "com"} {
		q = append(q, byte(len(label)))
		q = append(q, label...)
	}
	q = append(q, 0x00)
	q = binary.BigEndian.AppendUint16(q, 0x0001) // A
	q = binary.BigEndian.AppendUint16(q, 0x0001) // IN
	return q
}

var _ = hex.EncodeToString

// holdConn opens a SOCKS5 CONNECT, leaves it completely idle for d, then
// sends a request and requires an answer. It is the long-download shape.
func holdConn(proxy, dest string, d, ping, timeout time.Duration) error {
	var dialer net.Dialer
	c, err := dialer.DialContext(context.Background(), "tcp", proxy)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(d + timeout))

	if err := socksHandshake(c); err != nil {
		return err
	}
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	if err := socksRequest(c, 0x01, host, uint16(port)); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	// Silence vs a byte every `ping`: an idle-reaper shows up as "silence
	// dies, pings survive"; a fixed lifetime dies either way.
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		step := time.Until(deadline)
		if ping > 0 && ping < step {
			step = ping
		}
		time.Sleep(step)
		if ping > 0 && time.Now().Before(deadline) {
			if _, err := c.Write([]byte{' '}); err != nil {
				return fmt.Errorf("ping write failed after %s: %w", d, err)
			}
		}
	}

	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host); err != nil {
		return fmt.Errorf("write after %s idle: %w", d, err)
	}
	buf := make([]byte, 32)
	if _, err := io.ReadFull(c, buf); err != nil {
		return fmt.Errorf("no response after %s idle: %w", d, err)
	}
	return nil
}
