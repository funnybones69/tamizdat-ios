package wgturnclient

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"
	"sync/atomic"
	"time"
)

const (
	bondMagic                     = "TZB2"
	bondVersion            byte   = 2
	bondHeaderLen                 = 16
	bondMaxBindJSON               = 4096
	bondSmallPacketMax            = 384
	bondReorderWindow             = 256
	bondReorderHold               = 30 * time.Millisecond
	bondBindMaxAttempts           = 8
	bondBindInitialBackoff        = 125 * time.Millisecond
	bondFlagLatency        uint16 = 1 << 0
	bondKnownDataFlags            = bondFlagLatency
)

type bondFrameType byte

const (
	bondFrameBind       bondFrameType = 1
	bondFrameBindWait   bondFrameType = 2
	bondFrameBindOK     bondFrameType = 3
	bondFrameBindConfig bondFrameType = 4
	bondFrameData       bondFrameType = 5
	bondFrameKeepalive  bondFrameType = 6
	bondFrameError      bondFrameType = 7
)

type bondFrame struct {
	Type    bondFrameType
	Flags   uint16
	Seq     uint64
	Payload []byte
}

type bondBindPayload struct {
	DeviceID    string `json:"device_id"`
	RunID       string `json:"run_id"`
	Token       string `json:"token"`
	Room        int    `json:"room"`
	Worker      int    `json:"worker"`
	LocalPort   string `json:"local_port"`
	WantConfig  bool   `json:"want_config"`
	Password    string `json:"password,omitempty"`
	LatencyLane bool   `json:"latency_lane,omitempty"`
}

type bondRunnerIdentity struct {
	RunID string
	Token string
}

type bondNegotiationError struct{ Reason string }

func (e bondNegotiationError) Error() string { return "BONDV2_NEGOTIATION: " + e.Reason }

func newBondRunnerIdentity() (bondRunnerIdentity, error) {
	runID, err := randomB64(16)
	if err != nil {
		return bondRunnerIdentity{}, fmt.Errorf("bond run id random: %w", err)
	}
	token, err := randomB64(32)
	if err != nil {
		return bondRunnerIdentity{}, fmt.Errorf("bond token random: %w", err)
	}
	return bondRunnerIdentity{RunID: runID, Token: token}, nil
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func encodeBondFrame(frame bondFrame) ([]byte, error) {
	if frame.Type == bondFrameBind && len(frame.Payload) > bondMaxBindJSON {
		return nil, fmt.Errorf("bind payload too large")
	}
	out := make([]byte, bondHeaderLen+len(frame.Payload))
	copy(out[0:4], bondMagic)
	out[4] = bondVersion
	out[5] = byte(frame.Type)
	binary.BigEndian.PutUint16(out[6:8], frame.Flags)
	binary.BigEndian.PutUint64(out[8:16], frame.Seq)
	copy(out[bondHeaderLen:], frame.Payload)
	return out, nil
}

func decodeBondFrame(buf []byte) (bondFrame, error) {
	if len(buf) < bondHeaderLen {
		return bondFrame{}, fmt.Errorf("bond frame too short")
	}
	if string(buf[0:4]) != bondMagic {
		return bondFrame{}, fmt.Errorf("bond bad magic")
	}
	if buf[4] != bondVersion {
		return bondFrame{}, fmt.Errorf("bond unsupported version %d", buf[4])
	}
	ft := bondFrameType(buf[5])
	if ft < bondFrameBind || ft > bondFrameError {
		return bondFrame{}, fmt.Errorf("bond unknown frame type %d", ft)
	}
	payload := buf[bondHeaderLen:]
	if ft == bondFrameBind && len(payload) > bondMaxBindJSON {
		return bondFrame{}, fmt.Errorf("bond bind payload too large")
	}
	return bondFrame{Type: ft, Flags: binary.BigEndian.Uint16(buf[6:8]), Seq: binary.BigEndian.Uint64(buf[8:16]), Payload: payload}, nil
}

func encodeBondBind(p bondBindPayload) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(b) > bondMaxBindJSON {
		return nil, fmt.Errorf("bind json too large")
	}
	flags := uint16(0)
	if p.LatencyLane {
		// The OpenWrt production server negotiates the independent latency
		// lane in the binary BIND header. Keep the JSON capability as well so
		// canonical servers that negotiate from the payload remain compatible.
		flags = bondFlagLatency
	}
	return encodeBondFrame(bondFrame{Type: bondFrameBind, Flags: flags, Payload: b})
}

func bondFramePayload(ft bondFrameType, payload []byte) ([]byte, error) {
	return encodeBondFrame(bondFrame{Type: ft, Payload: payload})
}

type bondScheduler struct {
	roomRR      int
	primary     int
	workerRR    map[int]int
	workers     []*WorkerSlot
	workerRooms []int
	rooms       []int
	roomWorkers map[int][]*WorkerSlot
}

func newBondScheduler() *bondScheduler {
	return &bondScheduler{
		workerRR:    make(map[int]int),
		roomWorkers: make(map[int][]*WorkerSlot),
	}
}

func (s *bondScheduler) ensureTopology(workers []*WorkerSlot) {
	if s.sameWorkerTopology(workers) {
		return
	}

	s.workers = append(s.workers[:0], workers...)
	s.workerRooms = s.workerRooms[:0]
	s.rooms = s.rooms[:0]
	for room := range s.roomWorkers {
		delete(s.roomWorkers, room)
	}
	for _, w := range workers {
		if w == nil {
			s.workerRooms = append(s.workerRooms, 0)
			continue
		}
		s.workerRooms = append(s.workerRooms, w.RoomID)
		if _, ok := s.roomWorkers[w.RoomID]; !ok {
			s.rooms = append(s.rooms, w.RoomID)
		}
		s.roomWorkers[w.RoomID] = append(s.roomWorkers[w.RoomID], w)
	}
	sort.Ints(s.rooms)
}

func (s *bondScheduler) invalidateTopology() {
	clear(s.workers)
	s.workers = s.workers[:0]
	s.workerRooms = s.workerRooms[:0]
	s.rooms = s.rooms[:0]
	for room, workers := range s.roomWorkers {
		clear(workers)
		delete(s.roomWorkers, room)
	}
}

func (s *bondScheduler) sameWorkerTopology(current []*WorkerSlot) bool {
	if len(s.workers) != len(current) || len(s.workerRooms) != len(current) {
		return false
	}
	for i := range current {
		if s.workers[i] != current[i] {
			return false
		}
		if current[i] != nil && s.workerRooms[i] != current[i].RoomID {
			return false
		}
	}
	return true
}

func (s *bondScheduler) choose(workers []*WorkerSlot, pkt []byte, size int) (*WorkerSlot, bool) {
	s.ensureTopology(workers)
	rooms := s.rooms
	if len(rooms) == 0 {
		return nil, false
	}
	if size <= bondSmallPacketMax {
		start := 0
		for i, room := range rooms {
			if room == s.primary {
				start = i
				break
			}
		}
		for i := 0; i < len(rooms); i++ {
			room := rooms[(start+i)%len(rooms)]
			if w, ok := s.chooseInRoom(room, pkt); ok {
				s.primary = room
				return w, true
			}
		}
		return nil, false
	}
	start := s.roomRR % len(rooms)
	for i := 0; i < len(rooms); i++ {
		roomIdx := (start + i) % len(rooms)
		room := rooms[roomIdx]
		if w, ok := s.chooseInRoom(room, pkt); ok {
			s.roomRR = (roomIdx + 1) % len(rooms)
			return w, true
		}
	}
	return nil, false
}

func (s *bondScheduler) activeRooms(workers []*WorkerSlot) []int {
	s.ensureTopology(workers)
	return s.rooms
}

func (s *bondScheduler) chooseInRoom(room int, pkt []byte) (*WorkerSlot, bool) {
	roomWorkers := s.roomWorkers[room]
	if len(roomWorkers) == 0 {
		return nil, false
	}
	start := s.workerRR[room] % len(roomWorkers)
	for i := 0; i < len(roomWorkers); i++ {
		idx := (start + i) % len(roomWorkers)
		w := roomWorkers[idx]
		select {
		case w.SendCh <- pkt:
			s.workerRR[room] = (idx + 1) % len(roomWorkers)
			return w, true
		default:
		}
	}
	return nil, false
}

func (s *bondScheduler) chooseAndSend(workers []*WorkerSlot, pkt []byte, size int) (*WorkerSlot, bool) {
	return s.choose(workers, pkt, size)
}

type bondReorderBuffer struct {
	expect uint64
	buf    map[uint64][]byte
	first  time.Time
	now    func() time.Time
	stats  *Stats
}

func newBondReorderBuffer(stats *Stats) *bondReorderBuffer {
	return &bondReorderBuffer{expect: 1, buf: make(map[uint64][]byte, bondReorderWindow), now: time.Now, stats: stats}
}

func (r *bondReorderBuffer) push(seq uint64, payload []byte) [][]byte {
	if seq == 0 {
		atomic.AddInt64(&r.stats.BondReorderLate, 1)
		return nil
	}
	if seq < r.expect {
		atomic.AddInt64(&r.stats.BondReorderLate, 1)
		return nil
	}
	if seq == r.expect {
		out := [][]byte{payload}
		r.expect++
		out = append(out, r.drainContiguous()...)
		if len(r.buf) == 0 {
			r.first = time.Time{}
		}
		return out
	}
	if _, exists := r.buf[seq]; exists {
		atomic.AddInt64(&r.stats.BondReorderLate, 1)
		return nil
	}
	if seq-r.expect >= bondReorderWindow {
		atomic.AddInt64(&r.stats.BondReorderGaps, 1)
		r.expect = seq
		r.buf = make(map[uint64][]byte, bondReorderWindow)
		r.first = time.Time{}
		return r.push(seq, payload)
	}
	cp := append([]byte(nil), payload...)
	r.buf[seq] = cp
	if r.first.IsZero() {
		r.first = r.now()
	}
	return nil
}

func (r *bondReorderBuffer) flushExpired() [][]byte {
	if len(r.buf) == 0 || r.first.IsZero() || r.now().Sub(r.first) < bondReorderHold {
		return nil
	}
	seqs := make([]int, 0, len(r.buf))
	for seq := range r.buf {
		seqs = append(seqs, int(seq))
	}
	sort.Ints(seqs)
	lowest := uint64(seqs[0])
	if lowest > r.expect {
		atomic.AddInt64(&r.stats.BondReorderGaps, int64(lowest-r.expect))
		r.expect = lowest
	}
	payload := r.buf[lowest]
	delete(r.buf, lowest)
	r.expect = lowest + 1
	out := [][]byte{payload}
	out = append(out, r.drainContiguous()...)
	if len(r.buf) == 0 {
		r.first = time.Time{}
	} else {
		r.first = r.now()
	}
	return out
}

func (r *bondReorderBuffer) flushAll() [][]byte {
	if len(r.buf) == 0 {
		return nil
	}
	seqs := make([]uint64, 0, len(r.buf))
	for seq := range r.buf {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	out := make([][]byte, 0, len(seqs))
	for _, seq := range seqs {
		if seq < r.expect {
			delete(r.buf, seq)
			atomic.AddInt64(&r.stats.BondReorderLate, 1)
			continue
		}
		if seq > r.expect {
			atomic.AddInt64(&r.stats.BondReorderGaps, int64(seq-r.expect))
		}
		out = append(out, r.buf[seq])
		delete(r.buf, seq)
		r.expect = seq + 1
	}
	r.first = time.Time{}
	return out
}

func (r *bondReorderBuffer) drainContiguous() [][]byte {
	var out [][]byte
	for {
		p, ok := r.buf[r.expect]
		if !ok {
			return out
		}
		delete(r.buf, r.expect)
		out = append(out, p)
		r.expect++
	}
}
