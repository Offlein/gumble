//go:build integration

package gumble

import (
	"crypto/tls"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestMurmurActivatesUDP(t *testing.T) {
	addr := os.Getenv("MUMBLE_UDP_TEST_ADDR")
	if addr == "" {
		t.Skip("set MUMBLE_UDP_TEST_ADDR to run against Murmur")
	}
	config := NewConfig()
	config.Username = "gumble-udp-integration"
	client, err := DialWithDialer(new(net.Dialer), addr, config, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec -- local test server
	if err != nil {
		t.Fatal(err)
	}
	defer client.Disconnect()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadUint32(&client.udpActive) == 1 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("Murmur did not return a valid encrypted UDP ping")
}
