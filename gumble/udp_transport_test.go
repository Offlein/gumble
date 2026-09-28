package gumble

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/talkkonnect/gumble/gumble/MumbleProto"
	"github.com/talkkonnect/gumble/gumble/cryptstate"
)

func testCryptMaterial() (key, clientIV, serverIV []byte) {
	return bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 16)
}

func TestWriteAudioUsesValidatedUDP(t *testing.T) {
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	clientConn, err := net.DialUDP("udp", nil, serverConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	key, clientIV, serverIV := testCryptMaterial()
	var serverCrypt cryptstate.State
	if err := serverCrypt.SetKey(key, serverIV, clientIV); err != nil {
		t.Fatal(err)
	}
	client := &Client{Config: NewConfig(), udpConn: clientConn}
	if err := client.udpCrypt.SetKey(key, clientIV, serverIV); err != nil {
		t.Fatal(err)
	}
	atomic.StoreUint32(&client.udpActive, 1)
	if err := client.writeAudio(audioCodecIDOpus, 0, 7, true, []byte{0xaa, 0xbb}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}

	if err := serverConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, _, err := serverConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := serverCrypt.Decrypt(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) < 1 || plain[0] != 0x80 {
		t.Fatalf("expected Opus/normal-target UDP packet, got %x", plain)
	}
}

func TestWriteAudioFallsBackToUDPTunnel(t *testing.T) {
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	client := &Client{Config: NewConfig(), Conn: NewConn(writer)}
	errC := make(chan error, 1)
	go func() {
		errC <- client.writeAudio(audioCodecIDOpus, 0, 7, false, []byte{0xaa}, nil, nil, nil)
	}()

	var header [6]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(header[:2]); got != 1 {
		t.Fatalf("expected UDPTunnel message type 1, got %d", got)
	}
	payload := make([]byte, binary.BigEndian.Uint32(header[2:]))
	if _, err := io.ReadFull(reader, payload); err != nil {
		t.Fatal(err)
	}
	if len(payload) < 1 || payload[0] != 0x80 {
		t.Fatalf("expected Opus/normal-target tunnel payload, got %x", payload)
	}
	if err := <-errC; err != nil {
		t.Fatal(err)
	}
}

func TestCryptSetupClientNonceResyncsDecryptDirection(t *testing.T) {
	key, clientIV, serverIV := testCryptMaterial()
	var server cryptstate.State
	if err := server.SetKey(key, serverIV, clientIV); err != nil {
		t.Fatal(err)
	}
	client := &Client{Config: &Config{ForceTCP: true}}
	if err := client.udpCrypt.SetKey(key, clientIV, serverIV); err != nil {
		t.Fatal(err)
	}

	first, err := server.Encrypt([]byte{0x20, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.udpCrypt.Decrypt(first); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Encrypt([]byte{0x20, 0x02}); err != nil { // dropped
		t.Fatal(err)
	}

	data, err := proto.Marshal(&MumbleProto.CryptSetup{ClientNonce: server.EncryptIV()})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.handleCryptSetup(data); err != nil {
		t.Fatal(err)
	}
	third, err := server.Encrypt([]byte{0x20, 0x03})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := client.udpCrypt.Decrypt(third); err != nil || !bytes.Equal(got, []byte{0x20, 0x03}) {
		t.Fatalf("resynchronized packet failed: %v, %x", err, got)
	}
}
