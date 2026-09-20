package seichannel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"time"
)

// KCP packets ride inside H264 SEI payloads (the AU itself stays a valid
// H264 stream, so the SFU forwards it untouched). Wire layout of one SEI
// payload:
//
//	[0..4]   = binding token (session isolation between concurrent pairs)
//	[4..8]   = sender's epoch (src, big-endian uint32)
//	[8..12]  = destination epoch (dst; 0 = broadcast to any listener)
//	[12..16] = CRC32(token || src || dst)
//	[16..]   = raw KCP packet bytes, or kcpBatchMagic + length-prefixed
//	           KCP packets when several were batched into one access unit.
//
// The dst field lets the server address downlink to one specific client even
// though the SFU forwards every frame to every participant: a receiver drops
// any frame whose dst is non-zero and not its own epoch. dst==0 is used
// before the sender has learned the receiver's epoch. Same scheme as the
// vp8channel transport, without the VP8 keepalive prefix (the H264 access
// unit is built by buildVideoAccessUnit and is already decodable).
const (
	tokenOff = 0
	srcOff   = 4
	dstOff   = 8
	crcOff   = 12
	// epochHdrLen is the size of the header above.
	epochHdrLen = 16
	// controlEpochFlag marks an epoch as belonging to the control-plane
	// session. Data-plane epochs are generated with this bit clear.
	controlEpochFlag uint32 = 0x80000000
)

// kcpBatchMagic prefixes a payload that carries several length-prefixed KCP
// packets instead of a single one.
var kcpBatchMagic = [4]byte{'O', 'L', 'S', 'B'} //nolint:gochecknoglobals // wire marker

func buildEpochHeaderTo(token, src, dst uint32) [epochHdrLen]byte {
	var hdr [epochHdrLen]byte
	binary.BigEndian.PutUint32(hdr[tokenOff:srcOff], token)
	binary.BigEndian.PutUint32(hdr[srcOff:dstOff], src)
	binary.BigEndian.PutUint32(hdr[dstOff:crcOff], dst)
	binary.BigEndian.PutUint32(hdr[crcOff:epochHdrLen], epochCRC(token, src, dst))
	return hdr
}

func epochCRC(token, src, dst uint32) uint32 {
	var buf [12]byte
	binary.BigEndian.PutUint32(buf[0:4], token)
	binary.BigEndian.PutUint32(buf[4:8], src)
	binary.BigEndian.PutUint32(buf[8:12], dst)
	return crc32.ChecksumIEEE(buf[:])
}

// parseEpochHeader returns (token, src, dst, ok). ok is false when the payload
// is too short or the header CRC does not validate.
func parseEpochHeader(payload []byte) (uint32, uint32, uint32, bool) {
	if len(payload) < epochHdrLen {
		return 0, 0, 0, false
	}
	token := binary.BigEndian.Uint32(payload[tokenOff:srcOff])
	src := binary.BigEndian.Uint32(payload[srcOff:dstOff])
	dst := binary.BigEndian.Uint32(payload[dstOff:crcOff])
	gotCRC := binary.BigEndian.Uint32(payload[crcOff:epochHdrLen])
	return token, src, dst, gotCRC == epochCRC(token, src, dst)
}

// splitKCPPayload feeds every KCP packet contained in payload to deliver,
// unpacking the batch framing when present.
func splitKCPPayload(payload []byte, deliver func([]byte)) {
	if len(payload) < len(kcpBatchMagic) ||
		!bytes.Equal(payload[:len(kcpBatchMagic)], kcpBatchMagic[:]) {
		deliver(payload)
		return
	}

	rest := payload[len(kcpBatchMagic):]
	for len(rest) > 0 {
		if len(rest) < 2 {
			return
		}
		size := int(binary.BigEndian.Uint16(rest[:2]))
		rest = rest[2:]
		if size == 0 || len(rest) < size {
			return
		}
		deliver(rest[:size])
		rest = rest[size:]
	}
}

// randomEpoch returns a non-zero data-plane epoch (high bit clear so it can
// never collide with control-plane epochs).
func randomEpoch() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand.Read on Linux essentially never fails; fall back to a
		// time-derived value rather than panic.
		//nolint:gosec // G115: bounded conversion verified by surrounding logic
		e := uint32(time.Now().UnixNano()) & ^controlEpochFlag
		if e == 0 {
			e = 1
		}
		return e
	}
	//nolint:gosec // G115: bounded conversion verified by surrounding logic
	e := binary.BigEndian.Uint32(b[:]) & ^controlEpochFlag
	if e == 0 {
		return 1
	}
	return e
}
