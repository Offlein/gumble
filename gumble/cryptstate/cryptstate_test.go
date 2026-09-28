package cryptstate

import (
	"bytes"
	"testing"
)

func TestLegacyMumblePacketVector(t *testing.T) {
	key := []byte{0x96, 0x8b, 0x1b, 0x0c, 0x53, 0x1e, 0x1f, 0x80, 0xa6, 0x1d, 0xcb, 0x27, 0x94, 0x09, 0x6f, 0x32}
	eiv := []byte{0x1e, 0x2a, 0x9b, 0xd0, 0x2d, 0xa6, 0x8e, 0x46, 0x26, 0x85, 0x83, 0xe9, 0x14, 0x2a, 0xff, 0x2a}
	div := []byte{0x73, 0x99, 0x9d, 0xa2, 0x03, 0x70, 0x00, 0x96, 0xef, 0x55, 0x06, 0x7a, 0x8b, 0xbe, 0x00, 0x07}
	plain := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	want := []byte{0x1f, 0xfc, 0xdd, 0xb4, 0x68, 0x13, 0x68, 0xb7, 0x92, 0x67, 0xca, 0x2d, 0xba, 0xb7, 0x0d, 0x44, 0xdf, 0x32, 0xd4}

	var sender State
	if err := sender.SetKey(key, eiv, div); err != nil {
		t.Fatal(err)
	}
	got, err := sender.Encrypt(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("ciphertext mismatch\n got %x\nwant %x", got, want)
	}

	var receiver State
	if err := receiver.SetKey(key, div, eiv); err != nil {
		t.Fatal(err)
	}
	got, err = receiver.Decrypt(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("plaintext mismatch: got %x want %x", got, plain)
	}
}

func TestBidirectionalPackets(t *testing.T) {
	key := bytes.Repeat([]byte{1}, blockSize)
	clientIV := bytes.Repeat([]byte{2}, blockSize)
	serverIV := bytes.Repeat([]byte{3}, blockSize)
	var client, server State
	if err := client.SetKey(key, clientIV, serverIV); err != nil {
		t.Fatal(err)
	}
	if err := server.SetKey(key, serverIV, clientIV); err != nil {
		t.Fatal(err)
	}
	for _, payload := range [][]byte{{0x20, 0x01}, {0x80, 0x00, 0x03, 0xaa, 0xbb, 0xcc}} {
		ciphertext, err := client.Encrypt(payload)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := server.Decrypt(ciphertext)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Fatalf("client->server failed: %v, %x", err, plain)
		}
		ciphertext, err = server.Encrypt(payload)
		if err != nil {
			t.Fatal(err)
		}
		plain, err = client.Decrypt(ciphertext)
		if err != nil || !bytes.Equal(plain, payload) {
			t.Fatalf("server->client failed: %v, %x", err, plain)
		}
	}
}
