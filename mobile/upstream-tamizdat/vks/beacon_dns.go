package vks

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
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
// The roomKey is HMAC-derived from the CLIENT SHORTID (RoomWakeKey), so a
// query both authenticates the caller and names the room. The shortid is
// the only credential — there is no separate deployment-wide wire key. The
// beacon carries the shortid as its second label so the server can derive
// the same selector and validate the user against the panel registry.
// Random DNS noise and strangers without a valid shortid cannot wake the
// server.
//
// No token can expire here: the beacon is shortid-based, and the room join
// it triggers uses a fresh anonymous guest registration.

// RunBeaconDNS serves the authoritative nameserver for zone, waking rooms on
// matching queries, until ctx is done. listenAddr is typically ":53".
//
// The zone is the DNS suffix that delegates to this server, e.g.
// "w.example.com" — a query for "<selector>.<shortid>.<nonce>.w.example.com"
// wakes that room (or assigns a provider room) for that user.
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

	// Beacon names are "<selector>.<shortid>.<nonce>.<zone>". The nonce
	// keeps every query unique so resolver caches never answer a wake on
	// the NS's behalf — a cached A record would silently swallow the
	// beacon. The selector is HMAC-derived from the shortid: a provider
	// selector (ProviderWakeKey) asks for a room on that provider, a room
	// selector (RoomWakeKey) wakes one specific armed room.
	lower := strings.ToLower(name)
	if suffix := "." + zone; strings.HasSuffix(lower, suffix) {
		left := strings.TrimSuffix(lower, suffix)
		if left != "" {
			labels := strings.Split(left, ".")
			selector := labels[0]
			beaconShortID := ""
			nonce := ""
			if len(labels) > 1 {
				beaconShortID = labels[1]
			}
			if len(labels) > 2 {
				nonce = labels[2]
			}
			if selector != "" && watch != nil {
				watch.mu.Lock()
				validator := watch.validateShortID
				watch.mu.Unlock()
				// The shortid is the only credential: validate it once for
				// both beacon kinds. A server without a validator (standalone
				// or test deployment) accepts any shortid, exactly as a
				// key-less deployment behaved before.
				if validator != nil && !validator(beaconShortID) {
					log.Printf("vks beacon dns: beacon name=%q REJECTED (bad shortid %q) from %s", name, beaconShortID, src)
				} else if roomKey, known := watch.matchRoomKey(selector, beaconShortID); known {
					// First: a specific armed-room wake.
					log.Printf("vks beacon dns: wake query name=%q roomKey=%q from %s", name, selector, src)
					watch.Wake(roomKey)
				} else if provider := matchProviderKey(selector, beaconShortID); provider != "" {
					// Second: a PROVIDER beacon — create/assign a room and
					// answer with its spec in a TXT record.
					log.Printf("vks beacon dns: provider beacon name=%q provider=%q shortid=%q from %s", name, provider, beaconShortID, src)
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					cfg, err := watch.AssignRoom(ctx, provider)
					cancel()
					// Provider flags ride in the same TXT RR: providers
					// whose credentials are dead (login required) tell
					// the client to re-upload cookies instead of a
					// silent empty answer. When the assign fails for a
					// login reason (or the room cap / a dead provider),
					// the answer carries an EMPTY spec + flags, not a
					// silent fallback.
					watch.mu.Lock()
					creds := watch.creds
					watch.mu.Unlock()
					flags := []string{}
					if creds != nil {
						if req := creds.LoginRequired(); len(req) > 0 {
							flags = append(flags, "login="+strings.Join(req, ","))
						}
					}
					if err != nil {
						log.Printf("vks beacon dns: assign %s failed: %v", provider, err)
						respondTXT(pc, src, msg, qend, beaconShortID, nonce, "", flags)
						return
					}
					spec := cfg.Provider + ":" + cfg.RoomURL
					log.Printf("vks beacon dns: assigned %s -> TXT spec for shortid=%q (flags %v)", provider, beaconShortID, flags)
					respondTXT(pc, src, msg, qend, beaconShortID, nonce, spec, flags)
					return
				}
			}
		}
	} else {
		log.Printf("vks beacon dns: query name=%q (no zone match) from %s", name, src)
	}

	// Build a minimal valid response: echo ID+question, QR=1 AA=1, one A
	// answer (127.0.0.1) for A queries so resolvers cache a benign result.
	resp := make([]byte, 0, len(msg)+16)
	resp = append(resp, msg[0], msg[1]) // ID
	resp = append(resp, 0x84, 0x00)     // QR=1, AA=1, RCODE=0
	resp = append(resp, msg[4], msg[5]) // QDCOUNT
	ancount := 0
	if qtype == 1 { // A
		ancount = 1
	}
	resp = append(resp, byte(ancount>>8), byte(ancount))
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT, ARCOUNT
	resp = append(resp, msg[12:qend+4]...)      // question
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

// SendWake emits the wake beacon for a specific armed room through the
// given DNS server (direct "host:53", or a whitelisted resolver). The
// client calls this just before connecting so the on-demand server joins
// the room in time. The query name is
// <roomKey>.<shortid>.<nonce>.<zone>: roomKey is derived from the caller's
// shortid (RoomWakeKey) and the shortid label lets the server derive the
// same selector and validate the user. The random nonce label makes every
// query unique so resolver caches never swallow the beacon with a stale A
// record.
func SendWake(ctx context.Context, dnsServer, zone, shortIDHex, roomKey string) error {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	sid := strings.ToLower(strings.TrimSpace(shortIDHex))
	if sid == "" {
		sid = "0"
	}
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("wake nonce: %w", err)
	}
	name := strings.ToLower(roomKey) + "." + sid + "." + hex.EncodeToString(nonce) + "." + zone + "."
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

// answerKey derives the per-user key that protects the room spec in the
// TXT answer. The old shared wire key never protected the answer (it only
// keyed the beacon selector), but with the shortid as the only credential
// the answer must not be readable by another user of the same server.
func answerKey(shortIDHex string) []byte {
	mac := hmac.New(sha256.New, shortIDKey(shortIDHex))
	mac.Write([]byte("vks-answer\x00"))
	return mac.Sum(nil)
}

// answerKeystream expands answerKey into n bytes of HMAC-SHA256 counter
// mode, bound to the beacon nonce so two answers to the same user never
// share a keystream.
func answerKeystream(shortIDHex, nonce string, n int) []byte {
	key := answerKey(shortIDHex)
	out := make([]byte, 0, n+sha256.Size)
	var ctr [4]byte
	for i := uint32(0); len(out) < n; i++ {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(nonce))
		binary.BigEndian.PutUint32(ctr[:], i)
		mac.Write(ctr[:])
		out = append(out, mac.Sum(nil)...)
	}
	return out[:n]
}

// encodeAnswerSpec encrypts the room spec for one user and authenticates
// it (encrypt-then-MAC). Format: "v1:" + base64url(ciphertext || tag16).
func encodeAnswerSpec(shortIDHex, nonce, spec string) string {
	// DNS character-strings cap at 255 bytes; 170 plaintext bytes leave
	// room for the 16-byte tag and base64 expansion inside one string.
	if len(spec) > 170 {
		spec = spec[:170]
	}
	plain := []byte(spec)
	ks := answerKeystream(shortIDHex, nonce, len(plain))
	ct := make([]byte, len(plain))
	for i := range plain {
		ct[i] = plain[i] ^ ks[i]
	}
	mac := hmac.New(sha256.New, answerKey(shortIDHex))
	mac.Write([]byte("mac\x00"))
	mac.Write([]byte(nonce))
	mac.Write(ct)
	ct = append(ct, mac.Sum(nil)[:16]...)
	return "v1:" + base64.RawURLEncoding.EncodeToString(ct)
}

// decodeAnswerSpec reverses encodeAnswerSpec. A string without the "v1:"
// prefix is returned verbatim: an older server (or a plaintext test
// vector) simply did not encrypt the spec. ok=false means the tag did not
// verify — the answer belongs to a different user or was tampered with.
func decodeAnswerSpec(shortIDHex, nonce, s string) (string, bool) {
	if !strings.HasPrefix(s, "v1:") {
		return s, true
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[3:])
	if err != nil || len(raw) < 16 {
		return "", false
	}
	ct, want := raw[:len(raw)-16], raw[len(raw)-16:]
	mac := hmac.New(sha256.New, answerKey(shortIDHex))
	mac.Write([]byte("mac\x00"))
	mac.Write([]byte(nonce))
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil)[:16], want) {
		return "", false
	}
	ks := answerKeystream(shortIDHex, nonce, len(ct))
	plain := make([]byte, len(ct))
	for i := range ct {
		plain[i] = ct[i] ^ ks[i]
	}
	return string(plain), true
}

// respondTXT answers a DNS query with a TXT record carrying the
// beacon-assignment answer: the FIRST character-string is the room spec
// encrypted for the beaconing shortid ("" when no room was assigned —
// e.g. login required), the following strings are plaintext `key=value`
// flags (e.g. "login=telemost,mts"). TTL 0.
func respondTXT(pc net.PacketConn, src net.Addr, msg []byte, qend int, shortIDHex, nonce, spec string, flags []string) {
	if len(flags) > 5 {
		flags = flags[:5]
	}
	stringsOut := make([][]byte, 0, 1+len(flags))
	stringsOut = append(stringsOut, []byte(encodeAnswerSpec(shortIDHex, nonce, spec)))
	for _, f := range flags {
		d := []byte(f)
		if len(d) > 200 {
			d = d[:200]
		}
		stringsOut = append(stringsOut, d)
	}
	rdlen := 0
	for _, s := range stringsOut {
		rdlen += 1 + len(s)
	}
	resp := make([]byte, 0, len(msg)+32+rdlen)
	resp = append(resp, msg[0], msg[1])         // ID
	resp = append(resp, 0x84, 0x00)             // QR=1, AA=1, RCODE=0
	resp = append(resp, msg[4], msg[5])         // QDCOUNT
	resp = append(resp, 0x00, 0x01)             // ANCOUNT=1 (TXT)
	resp = append(resp, 0x00, 0x00, 0x00, 0x00) // NSCOUNT, ARCOUNT
	resp = append(resp, msg[12:qend+4]...)      // question
	// name pointer, TYPE TXT (16), CLASS IN, TTL 0, RDLENGTH, RDATA
	resp = append(resp, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00)
	resp = append(resp, byte(rdlen>>8), byte(rdlen))
	for _, s := range stringsOut {
		resp = append(resp, byte(len(s)))
		resp = append(resp, s...)
	}
	_, _ = pc.WriteTo(resp, src)
}

// SendWakeProvider asks the server to CREATE/ASSIGN a room on the given
// provider and returns the assigned room spec ("provider:roomURL") and
// the answer's key=value flags from the DNS TXT answer. This is the
// beacon-assignment flow: the client beacons a selector derived from its
// shortid, the server creates a fresh room (WB/Jazz) or assigns an
// armed/pool one (Telemost/MTS) and answers in-band. shortIDHex is the
// client's tamizdat user identity and the ONLY credential — it is both
// the selector key and the answer key.
//
// The answer's first TXT character-string is the encrypted room spec
// ("" when the server could not assign a room — e.g. login required);
// the strings after it are flags (e.g. "login=telemost,mts"). On a
// successful (ANCOUNT>=1) answer the package-level login-required set is
// refreshed from the flags, so LoginRequiredProviders() reflects the
// server's view (see nativeconn.go for the empty-spec fail-fast).
func SendWakeProvider(ctx context.Context, dnsServer, zone, provider, shortIDHex string) (string, []string, error) {
	zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
	sid := strings.ToLower(strings.TrimSpace(shortIDHex))
	if sid == "" {
		sid = "0"
	}
	providerKey := ProviderWakeKey(sid, provider)
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return "", nil, fmt.Errorf("wake nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	name := strings.ToLower(providerKey) + "." + sid + "." + nonceHex + "." + zone + "."
	query := buildTXTQuery(name)
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(ctx, "udp", dnsServer)
	if err != nil {
		return "", nil, fmt.Errorf("wake dial %s: %w", dnsServer, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(12 * time.Second))
	if _, err := c.Write(query); err != nil {
		return "", nil, fmt.Errorf("wake write: %w", err)
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return "", nil, fmt.Errorf("wake read: %w", err)
	}
	strs, err := parseTXTAnswerAll(buf[:n])
	if err != nil {
		return "", nil, err
	}
	if len(strs) == 0 {
		return "", nil, fmt.Errorf("wake answer: no TXT record")
	}
	spec, ok := decodeAnswerSpec(sid, nonceHex, strs[0])
	if !ok {
		return "", nil, fmt.Errorf("wake answer: spec authentication failed for shortid %q", sid)
	}
	flags := strs[1:]
	recordLoginFlags(flags)
	return spec, flags, nil
}

// recordLoginFlags folds a beacon answer's "login=..." flag into the
// package-level set (replaced wholesale on every successful answer).
func recordLoginFlags(flags []string) {
	var providers []string
	for _, f := range flags {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k != "login" {
			continue
		}
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(strings.ToLower(p))
			if p != "" {
				providers = append(providers, p)
			}
		}
	}
	loginRequiredMu.Lock()
	loginRequiredSet = providers
	loginRequiredMu.Unlock()
}

// loginRequiredMu guards loginRequiredSet — the client-side copy of the
// server's login-required providers, refreshed on every beacon answer.
var (
	loginRequiredMu  sync.Mutex
	loginRequiredSet []string
)

// LoginRequiredProviders returns the sorted providers the server's last
// beacon answer flagged as needing a login (dead cookies). The iOS app
// surfaces this to prompt for a cookie re-upload; an empty result means
// every provider is believed healthy.
func LoginRequiredProviders() []string {
	loginRequiredMu.Lock()
	defer loginRequiredMu.Unlock()
	if len(loginRequiredSet) == 0 {
		return nil
	}
	out := append([]string(nil), loginRequiredSet...)
	sort.Strings(out)
	return out
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

// parseTXTAnswerAll extracts every TXT character-string from the FIRST
// answer record: [0] is the encrypted room spec (possibly empty — the
// server could not assign a room), [1:] are the plaintext key=value flags.
func parseTXTAnswerAll(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("short response")
	}
	ancount := int(msg[6])<<8 | int(msg[7])
	if ancount < 1 {
		return nil, fmt.Errorf("no answer")
	}
	// skip the question
	_, qend, ok := decodeQName(msg, 12)
	if !ok || qend+4 > len(msg) {
		return nil, fmt.Errorf("bad question")
	}
	off := qend + 4
	// first answer: name (possibly a pointer), then TYPE/CLASS/TTL/RDLENGTH/RDATA
	if off < len(msg) && msg[off]&0xC0 == 0xC0 {
		off += 2 // compression pointer
	} else {
		_, off, ok = decodeQName(msg, off)
		if !ok {
			return nil, fmt.Errorf("bad answer name")
		}
	}
	if off+10 > len(msg) {
		return nil, fmt.Errorf("truncated answer")
	}
	qtype := int(msg[off])<<8 | int(msg[off+1])
	if qtype != 16 {
		return nil, fmt.Errorf("not TXT (type %d)", qtype)
	}
	rdlen := int(msg[off+8])<<8 | int(msg[off+9])
	off += 10
	if off+rdlen > len(msg) || rdlen < 1 {
		return nil, fmt.Errorf("bad RDATA")
	}
	var out []string
	end := off + rdlen
	for off < end && off < len(msg) {
		strLen := int(msg[off])
		off++
		if off+strLen > end || off+strLen > len(msg) {
			return nil, fmt.Errorf("bad TXT string")
		}
		out = append(out, string(msg[off:off+strLen]))
		off += strLen
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty TXT RDATA")
	}
	return out, nil
}
