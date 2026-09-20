// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package datachannel

import (
	"fmt"
	"log"
)

// message is a parsed DataChannel message.
type message interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
	String() string
}

// messageType is the first byte in a DataChannel message that specifies type.
type messageType byte

// DataChannel Message Types.
const (
	dataChannelAck  messageType = 0x02
	dataChannelOpen messageType = 0x03
	// dataChannelOpenLegacy is the pre-RFC8832 draft OPEN type. The MTS Link
	// "odin" SFU sends its DCEP OPEN with this type; browsers accept it.
	dataChannelOpenLegacy messageType = 0x01
)

func (t messageType) String() string {
	switch t {
	case dataChannelAck:
		return "DataChannelAck"
	case dataChannelOpen:
		return "DataChannelOpen"
	default:
		return fmt.Sprintf("Unknown MessageType: %d", t)
	}
}

// parse accepts raw input and returns a DataChannel message.
func parse(raw []byte) (message, error) {
	if len(raw) == 0 {
		return nil, ErrDataChannelMessageTooShort
	}
	if raw[0] == 0x01 { // odin SFU custom frame — log for protocol analysis
		log.Printf("[dcep] odin type-1 frame len=%d hex=%x", len(raw), raw)
	}

	var msg message
	switch messageType(raw[0]) {
	case dataChannelOpen:
		msg = &channelOpen{}
	case dataChannelOpenLegacy:
		if len(raw) < 12 {
			// The MTS odin SFU sends a short type-1 frame (6 bytes) that is
			// neither a legacy OPEN nor an ACK — treat it as an
			// acknowledgment so the handshake completes.
			msg = &channelAck{}
		} else {
			msg = &channelOpen{}
		}
	case dataChannelAck:
		msg = &channelAck{}
	default:
		return nil, fmt.Errorf("%w %v", ErrInvalidMessageType, messageType(raw[0]))
	}

	if err := msg.Unmarshal(raw); err != nil {
		return nil, err
	}

	return msg, nil
}

// parseExpectDataChannelOpen parses a DataChannelOpen message
// or throws an error.
func parseExpectDataChannelOpen(raw []byte) (*channelOpen, error) {
	if len(raw) == 0 {
		return nil, ErrDataChannelMessageTooShort
	}

	if actualTyp := messageType(raw[0]); actualTyp != dataChannelOpen && actualTyp != dataChannelOpenLegacy {
		return nil, fmt.Errorf("%w expected(%s) actual(%s)", ErrUnexpectedDataChannelType, actualTyp, dataChannelOpen)
	}

	msg := &channelOpen{}
	if err := msg.Unmarshal(raw); err != nil {
		return nil, err
	}

	return msg, nil
}

// TryMarshalUnmarshal attempts to marshal and unmarshal a message. Added for fuzzing.
func TryMarshalUnmarshal(msg []byte) int {
	message, err := parse(msg)
	if err != nil {
		return 0
	}

	_, err = message.Marshal()
	if err != nil {
		return 0
	}

	return 1
}
