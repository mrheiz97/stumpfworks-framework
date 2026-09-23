package ldap

import (
	"bytes"
	"errors"
	"io"
	"net"
)

var errInvalidFrame = errors.New("invalid directory response frame")

// framedConn validates complete, bounded LDAP BER messages before handing them
// to go-ldap. A byte budget alone does not bound nested decoder amplification.
// Limits are local to this connection; BER package globals are never changed.
type framedConn struct {
	net.Conn
	buffer *bytes.Reader
	frames int
}

func (c *framedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.buffer == nil || c.buffer.Len() == 0 {
		if c.frames >= 16 {
			return 0, errInvalidFrame
		}
		var prefix [2]byte
		if _, err := io.ReadFull(c.Conn, prefix[:]); err != nil {
			return 0, err
		}
		if prefix[0] != 0x30 {
			return 0, errInvalidFrame
		}
		header := append([]byte(nil), prefix[:]...)
		length := int(prefix[1])
		if prefix[1]&0x80 != 0 {
			octets := int(prefix[1] & 0x7f)
			if octets < 1 || octets > 4 {
				return 0, errInvalidFrame
			}
			extra := make([]byte, octets)
			if _, err := io.ReadFull(c.Conn, extra); err != nil {
				return 0, err
			}
			header = append(header, extra...)
			length = 0
			for _, value := range extra {
				// Check before shifting, including on 32-bit targets.
				if length > (1<<20)>>8 {
					return 0, errInvalidFrame
				}
				length = length<<8 | int(value)
			}
		}
		if length > (1<<20)-len(header) {
			return 0, errInvalidFrame
		}
		frame := make([]byte, len(header)+length)
		copy(frame, header)
		if _, err := io.ReadFull(c.Conn, frame[len(header):]); err != nil {
			return 0, err
		}
		if err := validateBERFrame(frame); err != nil {
			return 0, err
		}
		c.buffer = bytes.NewReader(frame)
		c.frames++
	}
	return c.buffer.Read(p)
}

func validateBERFrame(frame []byte) error {
	if len(frame) < 2 || len(frame) > 1<<20 || frame[0] != 0x30 {
		return errInvalidFrame
	}
	nodes := 0
	end, err := validateBERElement(frame, 0, &nodes)
	if err != nil || end != len(frame) {
		return errInvalidFrame
	}
	return nil
}

func validateBERElement(data []byte, depth int, nodes *int) (int, error) {
	*nodes++
	if depth > 32 || *nodes > 4096 || len(data) < 2 {
		return 0, errInvalidFrame
	}
	tag := data[0]
	index := 1
	if tag&0x1f == 0x1f {
		// Bounded high-tag-number form; contents of primitive octet strings
		// are not interpreted as BER and may contain arbitrary bytes.
		for count := 0; ; count++ {
			if count >= 5 || index >= len(data) {
				return 0, errInvalidFrame
			}
			value := data[index]
			index++
			if value&0x80 == 0 {
				break
			}
		}
	}
	if index >= len(data) {
		return 0, errInvalidFrame
	}
	length := int(data[index])
	index++
	if length&0x80 != 0 {
		octets := length & 0x7f
		if octets < 1 || octets > 4 || index+octets > len(data) {
			return 0, errInvalidFrame
		}
		length = 0
		for _, value := range data[index : index+octets] {
			if length > (1<<20)>>8 {
				return 0, errInvalidFrame
			}
			length = length<<8 | int(value)
		}
		index += octets
	}
	if length > len(data)-index {
		return 0, errInvalidFrame
	}
	end := index + length
	if tag&0x20 != 0 {
		for index < end {
			consumed, err := validateBERElement(data[index:end], depth+1, nodes)
			if err != nil {
				return 0, err
			}
			index += consumed
		}
	}
	return end, nil
}
