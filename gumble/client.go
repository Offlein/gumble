package gumble

import (
	"crypto/tls"
	"errors"
	"math"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/talkkonnect/gumble/gumble/MumbleProto"
	"github.com/talkkonnect/gumble/gumble/cryptstate"
	"github.com/talkkonnect/gumble/gumble/varint"
)

// State is the current state of the client's connection to the server.
type State int

const (
	// StateDisconnected means the client is no longer connected to the server.
	StateDisconnected State = iota

	// StateConnected means the client is connected to the server and is
	// syncing initial information. This is an internal state that will
	// never be returned by Client.State().
	StateConnected

	// StateSynced means the client is connected to a server and has been sent
	// the server state.
	StateSynced
)

// ClientVersion is the protocol version that Client implements.
const ClientVersion = 1<<16 | 4<<8 | 0

// Client is the type used to create a connection to a server.
type Client struct {
	// The User associated with the client.
	Self *User
	// The client's configuration.
	Config *Config
	// The underlying Conn to the server.
	Conn *Conn

	// The users currently connected to the server.
	Users Users
	// The connected server's channels.
	Channels    Channels
	permissions map[uint32]*Permission
	tmpACL      *ACL

	// Ping stats
	tcpPacketsReceived uint32
	tcpPingTimes       [12]float32
	tcpPingAvg         uint32
	tcpPingVar         uint32

	udpMu      sync.Mutex
	udpConn    *net.UDPConn
	udpCrypt   cryptstate.State
	udpStarted uint32
	udpActive  uint32
	udpPackets uint32
	udpResync  int64

	// A collection containing the server's context actions.
	ContextActions ContextActions

	// The audio encoder used when sending audio to the server.
	AudioEncoder AudioEncoder
	audioCodec   AudioCodec
	// To whom transmitted audio will be sent. The VoiceTarget must have already
	// been sent to the server for targeting to work correctly. Setting to nil
	// will disable voice targeting (i.e. switch back to regular speaking).
	VoiceTarget *VoiceTarget

	state uint32

	// volatile is held by the client when the internal data structures are being
	// modified.
	volatile rpwMutex

	connect         chan *RejectError
	end             chan struct{}
	disconnectEvent DisconnectEvent
}

// Dial is an alias of DialWithDialer(new(net.Dialer), addr, config, nil).
func Dial(addr string, config *Config) (*Client, error) {
	return DialWithDialer(new(net.Dialer), addr, config, nil)
}

// DialWithDialer connects to the Mumble server at the given address.
//
// The function returns after the connection has been established, the initial
// server information has been synced, and the OnConnect handlers have been
// called.
//
// nil and an error is returned if server synchronization does not complete by
// min(time.Now() + dialer.Timeout, dialer.Deadline), or if the server rejects
// the client.
func DialWithDialer(dialer *net.Dialer, addr string, config *Config, tlsConfig *tls.Config) (*Client, error) {
	start := time.Now()

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Conn:     NewConn(conn),
		Config:   config,
		Users:    make(Users),
		Channels: make(Channels),

		permissions: make(map[uint32]*Permission),

		state: uint32(StateConnected),

		connect: make(chan *RejectError),
		end:     make(chan struct{}),
	}
	if !config.ForceTCP {
		// UDP is optional: leave the control connection alive and use TCP
		// tunneling if a UDP socket cannot be opened.
		if udpConn, udpErr := dialer.Dial("udp", addr); udpErr == nil {
			if conn, ok := udpConn.(*net.UDPConn); ok {
				client.udpConn = conn
			} else {
				udpConn.Close()
			}
		}
	}

	go client.readRoutine()

	// Initial packets
	versionPacket := MumbleProto.Version{
		Version:   proto.Uint32(ClientVersion),
		Release:   proto.String("gumble"),
		Os:        proto.String(runtime.GOOS),
		OsVersion: proto.String(runtime.GOARCH),
	}
	authenticationPacket := MumbleProto.Authenticate{
		Username: &client.Config.Username,
		Password: &client.Config.Password,
		Opus:     proto.Bool(getAudioCodec(audioCodecIDOpus) != nil),
		Tokens:   client.Config.Tokens,
	}
	client.Conn.WriteProto(&versionPacket)
	client.Conn.WriteProto(&authenticationPacket)

	go client.pingRoutine()

	var timeout <-chan time.Time
	{
		var deadline time.Time
		if !dialer.Deadline.IsZero() {
			deadline = dialer.Deadline
		}
		if dialer.Timeout > 0 {
			diff := start.Add(dialer.Timeout)
			if deadline.IsZero() || diff.Before(deadline) {
				deadline = diff
			}
		}
		if !deadline.IsZero() {
			timer := time.NewTimer(deadline.Sub(start))
			defer timer.Stop()
			timeout = timer.C
		}
	}

	select {
	case <-timeout:
		client.Conn.Close()
		client.closeUDP()
		return nil, errors.New("gumble: synchronization timeout")
	case err := <-client.connect:
		if err != nil {
			client.Conn.Close()
			client.closeUDP()
			return nil, err
		}

		return client, nil
	}
}

// State returns the current state of the client.
func (c *Client) State() State {
	return State(atomic.LoadUint32(&c.state))
}

// AudioOutgoing creates a new channel that outgoing audio data can be written
// to. The channel must be closed after the audio stream is completed. Only
// a single channel should be open at any given time (i.e. close the channel
// before opening another).
func (c *Client) AudioOutgoing() chan<- AudioBuffer {
	ch := make(chan AudioBuffer)
	go func() {
		var seq int64
		previous := <-ch
		for p := range ch {
			previous.writeAudio(c, seq, false)
			previous = p
			seq = (seq + 1) % math.MaxInt32
		}
		if previous != nil {
			previous.writeAudio(c, seq, true)
		}
	}()
	return ch
}

// pingRoutine sends ping packets to the server at regular intervals.
func (c *Client) pingRoutine() {
	ticker := time.NewTicker(time.Second * 5)
	defer ticker.Stop()

	var timestamp uint64
	var tcpPingAvg float32
	var tcpPingVar float32
	packet := MumbleProto.Ping{
		Timestamp:  &timestamp,
		TcpPackets: &c.tcpPacketsReceived,
		TcpPingAvg: &tcpPingAvg,
		TcpPingVar: &tcpPingVar,
	}

	t := time.Now()
	for {
		timestamp = uint64(t.UnixNano())
		tcpPingAvg = math.Float32frombits(atomic.LoadUint32(&c.tcpPingAvg))
		tcpPingVar = math.Float32frombits(atomic.LoadUint32(&c.tcpPingVar))
		c.Conn.WriteProto(&packet)
		c.sendUDPPing(timestamp)

		select {
		case <-c.end:
			return
		case t = <-ticker.C:
			// continue to top of loop
		}
	}
}

// readRoutine reads protocol buffer messages from the server.
func (c *Client) readRoutine() {
	c.disconnectEvent = DisconnectEvent{
		Client: c,
		Type:   DisconnectError,
	}

	for {
		pType, data, err := c.Conn.ReadPacket()
		if err != nil {
			break
		}
		if int(pType) < len(handlers) {
			handlers[pType](c, data)
		}
	}

	wasSynced := c.State() == StateSynced
	atomic.StoreUint32(&c.state, uint32(StateDisconnected))
	c.closeUDP()
	close(c.end)
	if wasSynced {
		c.Config.Listeners.onDisconnect(&c.disconnectEvent)
	}
}

func (c *Client) startUDP() {
	if c.Config.ForceTCP || c.udpConn == nil || !atomic.CompareAndSwapUint32(&c.udpStarted, 0, 1) {
		return
	}
	go c.udpRoutine()
	// Associate our UDP source port as soon as CryptSetup completes instead of
	// waiting for the next five-second control ping.
	c.sendUDPPing(uint64(time.Now().UnixNano()))
}

func (c *Client) closeUDP() {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if c.udpConn != nil {
		_ = c.udpConn.Close()
		c.udpConn = nil
	}
}

func (c *Client) udpRoutine() {
	var packet [65535]byte
	for {
		c.udpMu.Lock()
		conn := c.udpConn
		c.udpMu.Unlock()
		if conn == nil {
			return
		}
		n, err := conn.Read(packet[:])
		if err != nil {
			return
		}
		plain, err := c.udpCrypt.Decrypt(packet[:n])
		if err != nil {
			// UDP is lossy. Ignore invalid or stale datagrams; a later valid
			// packet re-establishes the path without harming TLS/TCP. Request a
			// nonce refresh at most once per five seconds.
			c.requestCryptResync()
			continue
		}
		atomic.StoreUint32(&c.udpActive, 1)
		atomic.AddUint32(&c.udpPackets, 1)
		_ = c.handleUDPPacket(plain)
	}
}

func (c *Client) requestCryptResync() {
	now := time.Now().Unix()
	last := atomic.LoadInt64(&c.udpResync)
	if now-last < 5 || !atomic.CompareAndSwapInt64(&c.udpResync, last, now) {
		return
	}
	_ = c.Conn.WriteProto(&MumbleProto.CryptSetup{})
}

func (c *Client) sendUDPPing(timestamp uint64) {
	if c.Config.ForceTCP || !c.udpCrypt.Ready() {
		return
	}
	var payload [1 + varint.MaxVarintLen]byte
	payload[0] = 0x20 // Mumble UDP Ping
	n := varint.Encode(payload[1:], int64(timestamp))
	if n > 0 {
		_ = c.sendUDP(payload[:1+n])
	}
}

func (c *Client) sendUDP(payload []byte) error {
	c.udpMu.Lock()
	defer c.udpMu.Unlock()
	if c.udpConn == nil {
		return errors.New("gumble: UDP transport is unavailable")
	}
	ciphertext, err := c.udpCrypt.Encrypt(payload)
	if err != nil {
		return err
	}
	_, err = c.udpConn.Write(ciphertext)
	return err
}

func (c *Client) writeAudio(format, target byte, sequence int64, final bool, data []byte, x, y, z *float32) error {
	payload, err := makeAudioPacket(format, target, sequence, final, data, x, y, z)
	if err != nil {
		return err
	}
	if !c.Config.ForceTCP && atomic.LoadUint32(&c.udpActive) == 1 {
		if err := c.sendUDP(payload); err == nil {
			return nil
		}
		atomic.StoreUint32(&c.udpActive, 0)
	}
	return c.Conn.WritePacket(1, payload)
}

// RequestUserList requests that the server's registered user list be sent to
// the client.
func (c *Client) RequestUserList() {
	packet := MumbleProto.UserList{}
	c.Conn.WriteProto(&packet)
}

// RequestBanList requests that the server's ban list be sent to the client.
func (c *Client) RequestBanList() {
	packet := MumbleProto.BanList{
		Query: proto.Bool(true),
	}
	c.Conn.WriteProto(&packet)
}

// Disconnect disconnects the client from the server.
func (c *Client) Disconnect() error {
	if c.State() == StateDisconnected {
		return errors.New("gumble: client is already disconnected")
	}
	c.disconnectEvent.Type = DisconnectUser
	c.Conn.Close()
	c.closeUDP()
	return nil
}

// Do executes f in a thread-safe manner. It ensures that Client and its
// associated data will not be changed during the lifetime of the function
// call.
func (c *Client) Do(f func()) {
	c.volatile.RLock()
	defer c.volatile.RUnlock()

	f()
}

// Send will send a Message to the server.
func (c *Client) Send(message Message) {
	message.writeMessage(c)
}
