// wgturn-e2e drives the PRODUCTION VK TURN client stack (wgturnclient via
// the socksstub bridge — the same code path the iOS Network Extension uses)
// and measures real download throughput through the tunnel.
//
// Flow: VK anonymous join -> TURN creds -> StartVKTurnUpstream (N workers,
// each its own relay allocation) -> wait for userspace WireGuard attach ->
// N parallel HTTP/1.1 downloads through the netstack -> aggregate Mbps.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anarki/samizdat-ios/mobile/socksstub"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	var (
		credsFile = flag.String("credsfile", "", "JSON file with pre-fetched TURN creds")
		peer      = flag.String("peer", "203.0.113.10:443", "wgturn server host:port")
		password  = flag.String("password", "", "wgturn password (= user shortid)")
		workers   = flag.Int("workers", 20, "TURN worker sessions (each = own allocation)")
		parallel  = flag.Int("parallel", 8, "parallel download connections")
		readMbps  = flag.Float64("readmbps", 0, "per-connection read cap in Mbit/s (0 = unlimited) - slows server bursts")
		target    = flag.String("target", "proof.ovh.net:80", "HTTP host:port to download from")
		path      = flag.String("path", "/files/100Mb.dat", "HTTP path")
		dur       = flag.Duration("dur", 30*time.Second, "measurement window")
	)
	flag.Parse()
	if *password == "" || *credsFile == "" {
		log.Fatal("-password (user shortid) and -credsfile required")
	}

	// 1. TURN creds from a pre-fetched file (the creds fetcher lives in the
	// tamizdat repo; the iOS flow fetches in Swift — Go side always consumes
	// ready JSON).
	credsRaw, err := os.ReadFile(*credsFile)
	if err != nil {
		log.Fatalf("credsfile: %v", err)
	}
	credsJSON := string(credsRaw)
	ctx := context.Background()

	// 2. Start the production upstream.
	log.Printf("starting vkturn upstream: peer=%s workers=%d", *peer, *workers)
	if s := socksstub.StartVKTurnUpstream(string(credsJSON), *peer, *password, "e2e-device", 19000, *workers); s != "" {
		log.Fatalf("StartVKTurnUpstream: %s", s)
	}

	// 3. Wait for userspace WG attach.
	log.Printf("waiting for WG config + netstack attach (up to 150s)...")
	var tunNet *netstack.Net
	deadline := time.Now().Add(150 * time.Second)
	for tunNet == nil && time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		tunNet = socksstub.VKTurnNetstack()
	}
	if tunNet == nil {
		log.Fatalf("netstack never attached (running=%t wgconf=%d bytes)",
			socksstub.TURNUpstreamRunning(), len(socksstub.TURNUpstreamWGConfig()))
	}
	log.Printf("netstack attached — tunnel live; measuring %v with %d parallel downloads", *dur, *parallel)

	// 4. Parallel downloads through the tunnel.
	var gotBytes atomic.Int64
	var wg sync.WaitGroup
	stopAt := time.Now().Add(*dur)
	for i := 0; i < *parallel; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for time.Now().Before(stopAt) {
				downloadOnce(ctx, tunNet, *target, *path, &gotBytes, stopAt, *readMbps)
			}
		}(i)
	}
	wg.Wait()
	fmt.Printf("RESULT workers=%d parallel=%d down=%.2f Mbit/s (%d bytes in %v)\n",
		*workers, *parallel, float64(gotBytes.Load()*8)/dur.Seconds()/1e6, gotBytes.Load(), *dur)
}

// downloadOnce opens one TCP connection through the tunnel netstack, issues
// a raw HTTP/1.1 GET and streams the body until the deadline, logging the
// per-connection lifecycle (dial time, first byte, total bytes, end cause).
func downloadOnce(ctx context.Context, tunNet *netstack.Net, target, path string, counter *atomic.Int64, stopAt time.Time, readMbps float64) {
	t0 := time.Now()
	dctx, dcancel := context.WithDeadline(ctx, stopAt)
	defer dcancel()
	conn, err := tunNet.DialContext(dctx, "tcp", target)
	if err != nil {
		log.Printf("dl: dial err after %v: %v", time.Since(t0).Round(time.Millisecond), err)
		return
	}
	defer conn.Close()
	host := target[:strings.LastIndex(target, ":")]
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	_ = conn.SetReadDeadline(stopAt)

	br := bufio.NewReader(conn)
	hdrBytes := 0
	statusLine := ""
	var allHdrs []string
	for {
		line, err := br.ReadString('\n')
		hdrBytes += len(line)
		trimmed := strings.TrimRight(line, "\r\n")
		if statusLine == "" {
			statusLine = trimmed
		} else if trimmed != "" {
			allHdrs = append(allHdrs, trimmed)
		}
		if err != nil {
			log.Printf("dl: header read err after %v (%d hdr bytes): %v", time.Since(t0).Round(time.Millisecond), hdrBytes, err)
			return
		}
		if line == "\r\n" {
			break
		}
	}
	log.Printf("dl: headers ok after %v (%d bytes) status=%q hdrs=%v", time.Since(t0).Round(time.Millisecond), hdrBytes, statusLine, allHdrs)
	buf := make([]byte, 32768)
	var body int64
	var bodyBuf []byte
	readStart := time.Now()
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if body == 0 {
				log.Printf("dl: first body byte after %v", time.Since(t0).Round(time.Millisecond))
			}
			body += int64(n)
			if len(bodyBuf) < 200 {
				bodyBuf = append(bodyBuf, buf[:min(n, 200-len(bodyBuf))]...)
			}
			counter.Add(int64(n))
			if readMbps > 0 {
				// Pace reads: keep the server's send rate under the relay
				// policer ceiling so nothing bursts into drops.
				wantElapsed := time.Duration(float64(body*8) / (readMbps * 1e6) * float64(time.Second))
				if lag := wantElapsed - time.Since(readStart); lag > 0 {
					time.Sleep(lag)
				}
			}
		}
		if err != nil {
			if body < 200 {
				log.Printf("dl: body ended after %v: %d body bytes, err=%v, body=%q headers=%q", time.Since(t0).Round(time.Millisecond), body, err, string(bodyBuf), statusLine)
			} else {
				log.Printf("dl: body ended after %v: %d body bytes, err=%v", time.Since(t0).Round(time.Millisecond), body, err)
			}
			return
		}
		if time.Now().After(stopAt) {
			return
		}
	}
}

var _ = net.IPv4zero
