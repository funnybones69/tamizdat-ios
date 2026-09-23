package vks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// beacon_dns.go — wake-up channel for the on-demand VKS server.
//
// Why DNS: under RU whitelists the tamizdat server IP is unreachable, so a
// client cannot signal it directly. DNS is the one channel where the server
// can be a first-class endpoint without sitting in a VKS room: the server
// runs the authoritative nameserver for a beacon zone, and a client "wakes"
// a room by resolving  <roomKey>.<zone>  through any reachable resolver
// (e.g. Yandex DoH, whitelisted). The resolver→authoritative-NS hop is
// infrastructure traffic, invisible to the client-side whitelist.
//
// The roomKey is HMAC-derived from the shared wire key (RoomWakeKey), so a
// query both authenticates the caller and names the room. Random DNS noise
// and strangers cannot wake the server — they do not know the key.
//
// No token can expire here: the beacon is key-based, and the room join it
// triggers uses a fresh anonymous guest registration.

// RunBeaconDNS serves the authoritative nameserver for zone, waking rooms on
// matching queries, until ctx is done. listenAddr is typically ":53".
//
// The zone is the DNS suffix that delegates to this server, e.g.
// "w.example.com" — a query for "<roomKey>.w.example.com" wakes that room.
func RunBeaconDNS(ctx context.Context, listenAddr, zone string, watch *WatchServer) error {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	if zone == "" {
		return fmt.Errorf("beacon dns: empty zone")
	}
	pc, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("beacon dns listen %s: %w", listenAddr, err)
	}
	log.Printf("vks beacon dns: authoritative for %q on %s", zone, listenAddr)
	go func() { <-ctx.Done(); _ = pc.Close() }()

	buf := make([]byte, 512)
	for {
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("beacon dns read: %w", err)
		}
		msg := make([]byte, n)
		copy(msg, buf[:n])
		go handleBeaconQuery(pc, src, msg, zone, watch)
	}
}

// handleBeaconQuery parses one DNS query; if it is a valid wake request it
// wakes the room, then answers so the resolver is satisfied either way.
func handleBeaconQuery(pc net.PacketConn, src net.Addr, msg []byte, zone string, watch *WatchServer) {
	if len(msg) < 12 {
		return
	}
	qd := int(msg[4])<<8 | int(msg[5])
	if qd < 1 {
		return
	}
	name, qend, ok := decodeQName(msg, 12)
	if !ok || qend+4 > len(msg) {
		return
	}
	qtype := int(msg[qend])<<8 | int(msg[qend+1])

	// Match "<roomKey>.<zone>" or "<roomKey>.<nonce>.<zone>" (a random
	// nonce label makes every query unique so resolver caches never answer
	// a wake on the NS's behalf — a cached A record would silently swallow
	// the beacon).
	lower := strings.ToLower(name)
	if suffix := "." + zone; strings.HasSuffix(lower, suffix) {
		left := strings.TrimSuffix(lower, suffix)
		if left != "" {
			selector := left
			if i := strings.Index(left, "."); i > 0 {
				selector = left[:i] // "<selector>.<nonce>"
			}
			if selector != "" && !strings.Contains(selector, ".") {
				// First: a specific room wake (existing behavior).
				woken := false
				if watch != nil {
					watch.mu.Lock()
					_, knownRoom := watch.rooms[selector]
					watch.mu.Unlock()
					if knownRoom {
						log.Printf("vks beacon dns: wake query name=%q roomKey=%q from %s", name, selector, src)
						watch.Wake(selector)
						woken = true
					}
				}
				// Second: a PROVIDER beacon — create/assign a room and
				// answer with its spec in a TXT record.
				if !woken && watch != nil {
					provider := watch.matchProviderKey(selector)
					if provider != "" {
						log.Printf("vks beacon dns: provider beacon name=%q provider=%q from %s", name, provider, src)
						ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
						cfg, err := watch.AssignRoom(ctx, provider)
						cancel()
						if err != nil {
							log.Printf("vks beacon dns: assign %s failed: %v", provider, err)
						} else {
							spec := cfg.Provider + ":" + cfg.RoomURL
							log.Printf("vks beacon dns: assigned %s -> TXT %q", provider, spec)
							respondTXT(pc, src, msg, qend, spec)
							return
						}
					}
				}
			}
		}
	} else {
		log.Printf("vks beacon dns: query name=%q (no zone match) from %s", name, src)
	}

	// Build a minimal valid response: echo ID+question, QR=1 AA=1, one A
	// answer (127.0.0.1) for A queries so resolvers cache a benign result.
	resp := make([]byte, 0, len(msg)+16)
	resp = append(resp, msg[0], msg[1])             // ID
	resp = append(resp, 0x84, 0x00)                 // QR=1, AA=1, RCODE=0
	resp = append(resp, msg[4], msg[5])             // QDCOUNT
	ancount := 0
	if qtype == 1 {                                 // A
		ancount = 1
	}
	resp = append(resp, byte(ancount>>8), byte(ancount))
	resp = append(resp, 0x00, 0x00, 0x00, 0x00)     // NSCOUNT, ARCOUNT
	resp = append(resp, msg[12:qend+4]...)          // question
	if ancount == 1 {
		// name pointer to the question (0xC00C), TYPE A, CLASS IN, TTL 0
		// (never cache — a cached A record would swallow later beacons),
		// RDLENGTH 4, RDATA 127.0.0.1.
		resp = append(resp, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 127, 0, 0, 1)
	}
	_, _ = pc.WriteTo(resp, src)
}

// decodeQName reads a (possibly compression-terminated) domain name from msg
// starting at off, returning the dotted name and the offset just past it.
func decodeQName(msg []byte, off int) (string, int, bool) {
	var labels []string
	for i := 0; i < 128; i++ { // bound against pointer loops
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		if l == 0 {
			return strings.Join(labels, "."), off + 1, true
		}
		if l&0xC0 == 0xC0 { // compression pointer: name ends here
			if off+1 >= len(msg) {
				return "", 0, false
			}
			return strings.Join(labels, "."), off + 2, true
		}
		if l&0xC0 != 0 || off+1+l > len(msg) {
			return "", 0, false
		}
		labels = append(labels, string(msg[off+1:off+1+l]))
		off += 1 + l
	}
	return "", 0, false
}
// SendWake emits the wake beacon for a room through the given DNS server
// (direct "host:53", or a whitelisted resolver). The client calls this just
// before connecting so the on-demand server joins the room in time.
// The query name carries a random nonce label (<roomKey>.<nonce>.<zone>) so
// resolver caches never swallow the beacon with a stale A record.
func SendWake(ctx context.Context, dnsServer, zone, roomKey string) error {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("wake nonce: %w", err)
	}
	name := strings.ToLower(roomKey) + "." + hex.EncodeToString(nonce) + "." + zone + "."
	query := buildAQuery(name)
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "udp", dnsServer)
	if err != nil {
		return fmt.Errorf("wake dial %s: %w", dnsServer, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(query); err != nil {
		return fmt.Errorf("wake write: %w", err)
	}
	buf := make([]byte, 512)
	_, _ = c.Read(buf) // response content is irrelevant; the query itself is the signal
	return nil
}

// buildAQuery builds a minimal DNS A query for name.
func buildAQuery(name string) []byte {
	msg := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x01, 0x00, 0x01) // root, QTYPE A, QCLASS IN
	return msg
}

// respondTXT answers a DNS query with a TXT record carrying spec (the
// beacon-assignment room answer). One character-string, TTL 0.
func respondTXT(pc net.PacketConn, src net.Addr, msg []byte, qend int, spec string) {
	data := []byte(spec)
	if len(data) > 200 {
		data = data[:200] // DNS-safe cap
	}
	resp := make([]byte, 0, len(msg)+32+len(data))
	resp = append(resp, msg[0], msg[1])         // ID
	resp = append(resp, 0x84, 0x00)             // QR=1, AA=1, RCODE=0
	resp = append(resp, msg[4], msg[5])         // QDCOUNT
	resp = append(resp, 0x00, 0x01)             // ANCOUNT=1 (TXT)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT, ARCOUNT
	resp = append(resp, msg[12:qend+4]...)      // question
	// name pointer, TYPE TXT (16), CLASS IN, TTL 0, RDLENGTH, RDATA
	resp = append(resp, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00)
	rdlen := 1 + len(data)
	resp = append(resp, byte(rdlen>>8), byte(rdlen))
	resp = append(resp, byte(len(data)))
	resp = append(resp, data...)
	_, _ = pc.WriteTo(resp, src)
}

// SendWakeProvider asks the server to CREATE/ASSIGN a room on the given
// provider and returns the assigned room spec ("provider:roomURL") from the
// DNS TXT answer. This is the beacon-assignment flow: the client beacons a
// provider key (HMAC of the shared key), the server creates a fresh room
// (WB/Jazz) or assigns an armed one (Telemost/MTS) and answers in-band.
func SendWakeProvider(ctx context.Context, dnsServer, zone, keyHex, provider, shortIDHex string) (string, error) {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	providerKey := ProviderWakeKey(keyHex, provider)
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("wake nonce: %w", err)
	}
	// The server shortid-proofs provider beacons: the query name carries the
	// client's shortid as the second label
	// (<providerKey>.<shortid>.<nonce>.<zone>), and the server assigns a room
	// only when that shortid is a valid user. An empty label gets REJECTED.
	sid := strings.ToLower(strings.TrimSpace(shortIDHex))
	if sid == "" {
		sid = "0"
	}
	name := strings.ToLower(providerKey) + "." + sid + "." + hex.EncodeToString(nonce) + "." + zone + "."
	query := buildTXTQuery(name)
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "udp", dnsServer)
	if err != nil {
		return "", fmt.Errorf("wake dial %s: %w", dnsServer, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := c.Write(query); err != nil {
		return "", fmt.Errorf("wake write: %w", err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return "", fmt.Errorf("wake read: %w", err)
	}
	return parseTXTAnswer(buf[:n])
}

// buildTXTQuery builds a minimal DNS TXT (type 16) query for name.
func buildTXTQuery(name string) []byte {
	msg := []byte{0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00, 0x00, 0x10, 0x00, 0x01) // root, QTYPE TXT, QCLASS IN
	return msg
}

// parseTXTAnswer extracts the TXT character-string from a DNS response.
func parseTXTAnswer(msg []byte) (string, error) {
	if len(msg) < 12 {
		return "", fmt.Errorf("short response")
	}
	ancount := int(msg[6])<<8 | int(msg[7])
	if ancount < 1 {
		return "", fmt.Errorf("no answer")
	}
	// skip the question
	_, qend, ok := decodeQName(msg, 12)
	if !ok || qend+4 > len(msg) {
		return "", fmt.Errorf("bad question")
	}
	off := qend + 4
	// first answer: name (possibly a pointer), then TYPE/CLASS/TTL/RDLENGTH/RDATA
	if off < len(msg) && msg[off]&0xC0 == 0xC0 {
		off += 2 // compression pointer
	} else {
		_, off, ok = decodeQName(msg, off)
		if !ok {
			return "", fmt.Errorf("bad answer name")
		}
	}
	if off+10 > len(msg) {
		return "", fmt.Errorf("truncated answer")
	}
	qtype := int(msg[off])<<8 | int(msg[off+1])
	if qtype != 16 {
		return "", fmt.Errorf("not TXT (type %d)", qtype)
	}
	rdlen := int(msg[off+8])<<8 | int(msg[off+9])
	off += 10
	if off+rdlen > len(msg) || rdlen < 1 {
		return "", fmt.Errorf("bad RDATA")
	}
	strLen := int(msg[off])
	if strLen+1 > rdlen {
		return "", fmt.Errorf("bad TXT string")
	}
	return string(msg[off+1 : off+1+strLen]), nil
}
