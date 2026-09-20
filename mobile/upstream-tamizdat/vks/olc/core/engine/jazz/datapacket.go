package jazz

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/uuid"
)

// DataPacket is the SaluteJazz datachannel wire framing: a protobuf-like
// envelope with field1 varint 0, field2{ field2 payload, field8 msgUUID }.

func encodeVarint(v uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, v)
	return buf[:n]
}

func encodeField(fieldNumber, wireType int, data []byte) []byte {
	tag := encodeVarint(uint64(fieldNumber)<<3 | uint64(wireType)) //nolint:gosec
	if wireType == 2 {
		ln := encodeVarint(uint64(len(data)))
		out := make([]byte, 0, len(tag)+len(ln)+len(data))
		out = append(out, tag...)
		out = append(out, ln...)
		out = append(out, data...)
		return out
	}
	out := make([]byte, 0, len(tag)+len(data))
	out = append(out, tag...)
	out = append(out, data...)
	return out
}

// EncodeDataPacket wraps a payload into a Jazz data packet.
func EncodeDataPacket(payload []byte) []byte {
	msgID := uuid.New().String()
	user := encodeField(2, 2, payload)
	user = append(user, encodeField(8, 2, []byte(msgID))...)
	dp := encodeField(1, 0, encodeVarint(0))
	dp = append(dp, encodeField(2, 2, user)...)
	return dp
}

// DecodeDataPacket extracts the payload from a Jazz data packet.
func DecodeDataPacket(raw []byte) ([]byte, bool) {
	userData, ok := parseFields(raw, 2)
	if !ok {
		return nil, false
	}
	return parseFields(userData, 2)
}

func parseFields(data []byte, target int) ([]byte, bool) {
	r := &byteReader{data: data}
	var result []byte
	for r.pos < len(r.data) {
		tagVal, err := binary.ReadUvarint(r)
		if err != nil {
			break
		}
		fieldNumber := int(tagVal >> 3)
		wireType := int(tagVal & 0x07)
		fieldData, ok := handleWire(r, wireType, len(data))
		if !ok {
			return result, len(result) > 0
		}
		if fieldNumber == target && wireType == 2 {
			result = fieldData
		}
	}
	return result, len(result) > 0
}

func handleWire(r *byteReader, wireType, dataLen int) ([]byte, bool) {
	switch wireType {
	case 0:
		_, _ = binary.ReadUvarint(r)
		return nil, true
	case 2:
		length, err := binary.ReadUvarint(r)
		if err != nil || length > uint64(dataLen-r.pos) { //nolint:gosec
			return nil, false
		}
		fd := make([]byte, length)
		n, err := r.Read(fd)
		if err != nil || uint64(n) != length { //nolint:gosec
			return nil, false
		}
		return fd, true
	case 1:
		r.pos += 8
		return nil, true
	case 5:
		r.pos += 4
		return nil, true
	default:
		return nil, false
	}
}

type byteReader struct {
	data []byte
	pos  int
}

func (b *byteReader) ReadByte() (byte, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	c := b.data[b.pos]
	b.pos++
	return c, nil
}

func (b *byteReader) Read(p []byte) (int, error) {
	if b.pos >= len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.pos:])
	b.pos += n
	return n, nil
}

var _ = fmt.Sprintf
