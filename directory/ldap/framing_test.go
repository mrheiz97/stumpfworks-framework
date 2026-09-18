package ldap

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type frameFixtureConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c frameFixtureConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func TestBERFrameResourceLimits(t *testing.T) {
	valid := ber.NewSequence("")
	valid.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, ""))
	valid.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string([]byte{0x30, 0x80, 0xff}), ""))
	if err := validateBERFrame(valid.Bytes()); err != nil {
		t.Fatal("primitive contents interpreted as structure")
	}
	root := ber.NewSequence("")
	for i := 0; i < 33; i++ {
		parent := ber.NewSequence("")
		parent.AppendChild(root)
		root = parent
	}
	wide := ber.NewSequence("")
	for i := 0; i < 4096; i++ {
		wide.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	}
	for _, frame := range [][]byte{nil, {0x30, 0x80}, {0x30, 0x85, 1, 2, 3, 4, 5}, {0x30, 3, 4, 5, 0}, {0x30, 0, 0}, {4, 0}, root.Bytes(), wide.Bytes()} {
		if !errors.Is(validateBERFrame(frame), errInvalidFrame) {
			t.Fatal("malformed or amplified frame accepted")
		}
	}
}

func TestFramedConnection(t *testing.T) {
	frame := []byte{0x30, 3, 2, 1, 1}
	raw := bytes.NewReader(append(append([]byte{}, frame...), frame...))
	guard := &framedConn{Conn: frameFixtureConn{reader: raw}}
	output := make([]byte, 2*len(frame))
	if _, err := io.ReadFull(guard, output); err != nil || !bytes.Equal(output, append(frame, frame...)) {
		t.Fatal("valid consecutive frames changed")
	}
	if guard.frames != 2 {
		t.Fatal("frame accounting changed")
	}
	oversized := bytes.NewReader([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff, 0})
	guard = &framedConn{Conn: frameFixtureConn{reader: oversized}}
	if _, err := guard.Read(make([]byte, 1)); !errors.Is(err, errInvalidFrame) || oversized.Len() != 1 {
		t.Fatal("oversized length not rejected before payload read")
	}
	guard = &framedConn{Conn: frameFixtureConn{reader: bytes.NewReader(bytes.Repeat(frame, 17))}}
	for i := 0; i < 16; i++ {
		if _, err := io.ReadFull(guard, make([]byte, len(frame))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := guard.Read(make([]byte, 1)); !errors.Is(err, errInvalidFrame) {
		t.Fatal("unbounded response frames accepted")
	}
}

func FuzzBERFrame(f *testing.F) {
	for _, seed := range [][]byte{{0x30, 3, 2, 1, 1}, {0x30, 0x80}, {0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x30, 2, 4, 0}} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		_ = validateBERFrame(data)
	})
}
