<img src="misc/gumble.svg" width="200" align="right">

# gumble

gumble is a [Mumble](https://mumble.info/) client implementation in Go

## TalkKonnect compatibility

- Multi-channel listening (`AddListeningChannel` and
  `RemoveListeningChannel`).
- Raw Opus payload and sequence values on received audio packets, used by
  TalkKonnect's multicast forwarding path.
- Final partial frame handling for `gumbleffmpeg`.

## UDP voice transport

The client establishes Mumble's regular TLS/TCP control channel first. After
`CryptSetup`, it sends authenticated legacy OCB2-AES128 UDP pings to associate
its UDP port with Murmur. Once a valid encrypted reply arrives, outgoing voice
uses UDP and incoming UDP voice follows the normal audio-listener path.

If UDP cannot be established or fails while sending, voice falls back to TCP
`UDPTunnel` without dropping the control connection. Set `Config.ForceTCP` to
deliberately retain the legacy TCP-only behavior.

The module path intentionally remains `github.com/talkkonnect/gumble` for
source compatibility. A TalkKonnect build can consume a maintained fork by
replacing that module requirement with the fork's tagged version.

## Validation

`go test ./gumble/...` covers legacy crypt-state vectors, UDP voice selection,
and TCP fallback. `go test -tags integration ./gumble` runs the optional Murmur
handshake test when `MUMBLE_UDP_TEST_ADDR` is set.

## License

MPL 2.0

## Original Author

Tim Cooper (<tim.cooper@layeh.com>)
