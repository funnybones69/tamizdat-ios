package wgturnclient

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultListen       = "127.0.0.1:9000"
	defaultWorkers      = workersPerGroup
	maxWorkers          = 72 // legacy single-room compatibility
	maxRooms            = 4
	maxWorkersPerRoom   = 20
	maxMultiRoomWorkers = maxRooms * maxWorkersPerRoom
	defaultVKAppID      = "6287487"
	defaultVKAppSecret  = "QbYic1K3lEV5kTGiqlq2"
	defaultUserAgent    = "Mozilla/5.0"
)

type EventFunc func(level, message string)

type Config struct {
	Listen               string
	PeerAddr             string
	Workers              int
	WorkersPerRoom       int
	UseUDP               bool
	UseTCP               bool
	VKHashes             []string
	SecondaryHash        string
	DeviceID             string
	ConnPassword         string
	VKAppID              string
	VKAppSecret          string
	UserAgent            string
	CaptchaMode          string
	NoDNS                bool
	PreloadedCreds       *Credentials
	PreloadedCredsByHash map[string]*Credentials
	OnConfig             func(string)
	OnEvent              EventFunc

	TurnHost    string
	TurnPort    string
	SNI         string
	SplitTunnel bool
}

type Runner struct {
	cfg Config

	vkAppID        atomic.Value
	vkAppSecret    atomic.Value
	captchaMode    atomic.Value
	noDNS          atomic.Bool
	userAgent      atomic.Value
	preloadedCreds atomic.Pointer[Credentials]

	captchaResultCh chan string
	vkSemaphore     chan struct{}
	captchaWVSem    chan struct{}

	cacheMutex         sync.Mutex
	cachedSuccessToken string
	cachedTokenUsages  int32
	groupAuthMutex     sync.Mutex
	roomCredsMu        sync.Mutex
	roomCreds          map[string]roomCredentialCacheEntry

	pauseFlag int32

	runtimeMu sync.Mutex
	cancel    context.CancelFunc
	localConn net.PacketConn
}

func New(cfg Config) (*Runner, error) {
	cfg.Listen = strings.TrimSpace(cfg.Listen)
	if cfg.Listen == "" {
		cfg.Listen = defaultListen
	}
	cfg.PeerAddr = strings.TrimSpace(cfg.PeerAddr)
	cfg.SecondaryHash = strings.TrimSpace(cfg.SecondaryHash)
	cfg.DeviceID = strings.TrimSpace(cfg.DeviceID)
	if cfg.DeviceID == "" {
		cfg.DeviceID = "unknown"
	}
	cfg.VKAppID = strings.TrimSpace(cfg.VKAppID)
	if cfg.VKAppID == "" {
		cfg.VKAppID = defaultVKAppID
	}
	cfg.VKAppSecret = strings.TrimSpace(cfg.VKAppSecret)
	if cfg.VKAppSecret == "" {
		cfg.VKAppSecret = defaultVKAppSecret
	}
	cfg.CaptchaMode = strings.TrimSpace(cfg.CaptchaMode)
	if cfg.CaptchaMode == "" {
		cfg.CaptchaMode = "rjs"
	}
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	if cfg.UserAgent == "" {
		cfg.UserAgent = defaultUserAgent
	}
	if !cfg.UseTCP && !cfg.UseUDP {
		cfg.UseTCP = true
	}
	cfg.VKHashes = normalizeHashes(cfg.VKHashes)
	if cfg.WorkersPerRoom > 0 {
		if len(cfg.VKHashes) < 1 || len(cfg.VKHashes) > maxRooms {
			return nil, fmt.Errorf("multi-room mode requires 1-%d unique rooms", maxRooms)
		}
		if cfg.WorkersPerRoom < 1 || cfg.WorkersPerRoom > maxWorkersPerRoom {
			return nil, fmt.Errorf("workers per room must be between 1 and %d", maxWorkersPerRoom)
		}
		if cfg.SecondaryHash != "" || cfg.PreloadedCreds != nil {
			return nil, fmt.Errorf("legacy fallback/preloaded credentials are incompatible with multi-room mode")
		}
		if len(cfg.PreloadedCredsByHash) != len(cfg.VKHashes) {
			return nil, fmt.Errorf("multi-room credentials must cover every room")
		}
		for _, hash := range cfg.VKHashes {
			if cfg.PreloadedCredsByHash[hash] == nil {
				return nil, fmt.Errorf("multi-room credentials missing configured room")
			}
		}
		cfg.Workers = len(cfg.VKHashes) * cfg.WorkersPerRoom
		if cfg.Workers > maxMultiRoomWorkers {
			return nil, fmt.Errorf("multi-room worker count exceeds %d", maxMultiRoomWorkers)
		}
	} else {
		cfg.Workers = normalizeWorkerCount(cfg.Workers)
	}
	if len(cfg.VKHashes) == 0 && cfg.PreloadedCreds != nil {
		cfg.VKHashes = []string{"preloaded"}
	}
	if cfg.PeerAddr == "" || len(cfg.VKHashes) == 0 {
		return nil, fmt.Errorf("нужны PeerAddr и VKHashes")
	}

	r := &Runner{
		cfg:             cfg,
		captchaResultCh: make(chan string, 1),
		vkSemaphore:     make(chan struct{}, 2),
		captchaWVSem:    make(chan struct{}, 1),
		roomCreds:       make(map[string]roomCredentialCacheEntry),
	}
	r.vkAppID.Store(cfg.VKAppID)
	r.vkAppSecret.Store(cfg.VKAppSecret)
	r.captchaMode.Store(cfg.CaptchaMode)
	r.userAgent.Store(cfg.UserAgent)
	r.noDNS.Store(cfg.NoDNS)
	if cfg.PreloadedCreds != nil {
		dup := cloneCredentials(cfg.PreloadedCreds)
		r.preloadedCreds.Store(dup)
	}
	for hash, creds := range cfg.PreloadedCredsByHash {
		r.updateRoomCreds(hash, creds)
	}
	return r, nil
}

func (r *Runner) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	if err := r.setRuntime(cancel, nil); err != nil {
		cancel()
		return err
	}
	defer func() {
		cancel()
		r.clearRuntime()
	}()

	peer, err := net.ResolveUDPAddr("udp", r.cfg.PeerAddr)
	if err != nil {
		return fmt.Errorf("ошибка разбора пира: %w", err)
	}

	tp := &TurnParams{
		Host:          r.cfg.TurnHost,
		Port:          r.cfg.TurnPort,
		Hashes:        r.cfg.VKHashes,
		SecondaryHash: r.cfg.SecondaryHash,
		Sni:           r.cfg.SNI,
	}

	localConn, err := net.ListenPacket("udp", r.cfg.Listen)
	if err != nil {
		return fmt.Errorf("ошибка слушателя %s: %w", r.cfg.Listen, err)
	}
	r.setLocalConn(localConn)
	defer localConn.Close()
	if uc, ok := localConn.(*net.UDPConn); ok {
		// This is one shared dispatcher socket, so retain the single-room
		// capacity. Per-worker TURN sockets use an adaptive memory profile.
		_ = uc.SetReadBuffer(singleRoomSocketBufSize)
		_ = uc.SetWriteBuffer(singleRoomSocketBufSize)
	}
	stopLocalConn := context.AfterFunc(runCtx, func() { _ = localConn.Close() })
	defer stopLocalConn()

	_, localPort, _ := net.SplitHostPort(r.cfg.Listen)
	if localPort == "" {
		localPort = "9000"
	}

	plans := buildWorkerGroupPlans(r.cfg.Workers, len(r.cfg.VKHashes), r.cfg.WorkersPerRoom)
	numGroups := len(plans)
	logicalRoomCount := len(r.cfg.VKHashes)
	if logicalRoomCount == 0 && numGroups > 0 {
		logicalRoomCount = 1
	}

	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	log.Printf("[КЛИЕНТ] VK App: %s", r.cfg.VKAppID)
	log.Printf("[КЛИЕНТ] Воркеров: %d (групп: %d, по %d)", r.cfg.Workers, numGroups, workersPerGroup)
	log.Printf("[КЛИЕНТ] Хешей: %d", len(r.cfg.VKHashes))
	log.Printf("[КЛИЕНТ] Слушаю: %s | Пир: %s", r.cfg.Listen, r.cfg.PeerAddr)
	proto := "TCP"
	if r.cfg.UseUDP {
		proto = "UDP"
	}
	log.Printf("[КЛИЕНТ] Протокол: %s", proto)
	log.Printf("[КЛИЕНТ] Device ID: %s", r.cfg.DeviceID)
	log.Printf("[КЛИЕНТ] Обход капчи: %s", r.getCaptchaMode())
	log.Println("[КЛИЕНТ] ═══════════════════════════════════════")
	memoryProfile := memoryProfileForWorkers(r.cfg.Workers)
	r.eventf("info", "runner start workers=%d groups=%d workersPerGroup=%d proto=%s socketBuf=%d sendQueue=%d preloaded=%t %s deviceIDLen=%d", r.cfg.Workers, numGroups, workersPerGroup, proto, memoryProfile.socketBufferSize, memoryProfile.workerSendBuffer, r.preloadedCreds.Load() != nil, credentialsSummary(r.preloadedCreds.Load()), len(r.cfg.DeviceID))

	stats := NewStats()
	shutdownCh := make(chan struct{})
	go func() {
		<-runCtx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcher(runCtx, localConn, stats)
	defer disp.Shutdown()

	configCh := make(chan string, 1)
	configDone := make(chan struct{})
	go func() {
		defer close(configDone)
		select {
		case rawConf, ok := <-configCh:
			if !ok || rawConf == "" {
				return
			}
			finalConf := ensureConfigMTU(rawConf)
			if r.cfg.SplitTunnel {
				finalConf = ModifyConfigForSplitTunnel(finalConf, peer.IP)
			}
			if r.cfg.OnConfig != nil {
				r.cfg.OnConfig(finalConf)
			}
		case <-runCtx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1
	roomWaitReady := make([]<-chan struct{}, logicalRoomCount)
	broker := &configBroker{ch: configCh}

	for g, plan := range plans {
		myWaitReady := roomWaitReady[plan.hashIndex]
		var mySignalReady chan<- struct{}
		if g+1 < numGroups && plans[g+1].hashIndex == plan.hashIndex {
			ch := make(chan struct{})
			mySignalReady = ch
			roomWaitReady[plan.hashIndex] = ch
		} else {
			roomWaitReady[plan.hashIndex] = nil
		}

		ids := make([]int, plan.workerCount)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		gID := g + 1
		cycle := time.Duration(defaultCycleSecs) * time.Second
		wg.Add(1)
		go func(groupID int, cycleDir time.Duration, workerIDs []int, startHashIndex int, waitR <-chan struct{}, sigR chan<- struct{}) {
			defer wg.Done()
			r.workerGroup(runCtx, groupID, startHashIndex, tp, peer, disp, localPort, r.cfg.UseUDP,
				broker, workerIDs, cycleDir, &r.pauseFlag, r.cfg.DeviceID, r.cfg.ConnPassword, stats, waitR, sigR)
		}(gID, cycle, ids, plan.hashIndex, myWaitReady, mySignalReady)
	}

	wg.Wait()
	close(configCh)
	<-configDone
	log.Println("[КЛИЕНТ] Все воркеры завершены")
	return nil
}

func (r *Runner) Shutdown() {
	r.runtimeMu.Lock()
	cancel := r.cancel
	localConn := r.localConn
	r.runtimeMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if localConn != nil {
		_ = localConn.Close()
	}
}

// UpdatePreloadedCreds atomically swaps the credentials that the next
// worker-group rotation will pick up via getCredsWithFallback. iOS
// callers refresh VK creds out-of-band (TURNCredsRefresher) and push
// the new snapshot in here so long-lived sessions stay authenticated
// past the original creds' 3600 s lifetime.
//
// A nil argument is a no-op — we never want to clear creds out from
// under a running rotation.
func (r *Runner) UpdatePreloadedCreds(creds *Credentials) {
	if creds == nil {
		return
	}
	dup := *creds
	dup.TurnURLs = append([]string(nil), creds.TurnURLs...)
	if len(creds.TurnServers) > 0 {
		dup.TurnServers = append([]TurnServer(nil), creds.TurnServers...)
	}
	r.preloadedCreds.Store(&dup)
	r.eventf("info", "preloaded creds updated %s", credentialsSummary(&dup))
}

func (r *Runner) eventf(level, format string, args ...interface{}) {
	if r == nil || r.cfg.OnEvent == nil {
		return
	}
	r.cfg.OnEvent(level, fmt.Sprintf(format, args...))
}

func credentialsSummary(creds *Credentials) string {
	if creds == nil {
		return "creds=none"
	}
	udp, tcp, turns := 0, 0, 0
	for _, s := range creds.TurnServers {
		scheme := strings.ToLower(strings.TrimSpace(s.Scheme))
		transport := strings.ToLower(strings.TrimSpace(s.Transport))
		if scheme == "turns" {
			turns++
		} else if transport == "tcp" {
			tcp++
		} else {
			udp++
		}
	}
	return fmt.Sprintf("creds v1=%d v2=%d transports=udp:%d,tcp:%d,turns:%d lifetime=%ds userLen=%d passLen=%d", len(creds.TurnURLs), len(creds.TurnServers), udp, tcp, turns, creds.Lifetime, len(creds.User), len(creds.Pass))
}

func (r *Runner) SetPaused(paused bool) {
	if paused {
		atomic.StoreInt32(&r.pauseFlag, 1)
		return
	}
	atomic.StoreInt32(&r.pauseFlag, 0)
}

func (r *Runner) SubmitCaptchaResult(result string) {
	r.drainCaptchaResult()
	r.captchaResultCh <- result
}

func (r *Runner) drainCaptchaResult() {
	select {
	case <-r.captchaResultCh:
	default:
	}
}

func (r *Runner) setRuntime(cancel context.CancelFunc, localConn net.PacketConn) error {
	r.runtimeMu.Lock()
	defer r.runtimeMu.Unlock()
	if r.cancel != nil {
		r.eventf("warn", "runner already started")
		return fmt.Errorf("runner already started")
	}
	r.cancel = cancel
	r.localConn = localConn
	return nil
}

func (r *Runner) setLocalConn(localConn net.PacketConn) {
	r.runtimeMu.Lock()
	r.localConn = localConn
	r.runtimeMu.Unlock()
}

func (r *Runner) clearRuntime() {
	r.runtimeMu.Lock()
	r.cancel = nil
	r.localConn = nil
	r.runtimeMu.Unlock()
}

func normalizeWorkerCount(n int) int {
	if n <= 0 {
		n = defaultWorkers
	}
	if n > maxWorkers {
		n = maxWorkers
	}
	if n < workersPerGroup {
		n = workersPerGroup
	}
	// The planner supports a final partial group (for example 20 => 12+8).
	// Preserve the exact requested count instead of silently flooring it.
	return n
}

func normalizeHashes(hashes []string) []string {
	result := make([]string, 0, len(hashes))
	seen := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		hash = strings.TrimSpace(hash)
		if hash == "" {
			continue
		}
		if _, duplicate := seen[hash]; duplicate {
			continue
		}
		seen[hash] = struct{}{}
		result = append(result, hash)
	}
	return result
}

func ensureConfigMTU(conf string) string {
	if strings.Contains(conf, "MTU =") {
		return conf
	}
	lines := strings.Split(conf, "\n")
	newLines := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		newLines = append(newLines, line)
		if strings.TrimSpace(line) == "[Interface]" {
			newLines = append(newLines, "MTU = 1280")
		}
	}
	return strings.Join(newLines, "\n")
}
