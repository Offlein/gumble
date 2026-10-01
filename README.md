<img src="misc/gumble.svg" width="200" align="right">

# gumble

gumble is a [Mumble](https://mumble.info/) client implementation in Go

#### About this fork
This fork takes the [talkkonnect/gumble](https://github.com/talkkonnect/gumble)
fork and uses the some things written specifically by the talKKonnect folks:
 - TalkKonnect multi-channel listening (AddListeningChannel, RemoveListeningChannel)
 - Existing voice-target behavior
 - Raw received Opus payload and packet sequence fields used by TalkKonnect multicast
 - The TalkKonnect FFmpeg partial-final-frame fix

Then it adds UDP functionality following, which was stolen/backported from the old
[Grumble server](https://github.com/mumble-voip/grumble implementation (this is an
actual server - otherwise irrelevant to what Gumble, a client, does). That
functionality was:
 - CryptSetup handling
 - Encrypted Mumble UDP negotiation, send, and receive
 - UDP voice after validation
 - TCP tunnel fallback and nonce resync

Fair warning, this code was merged by me (Offlein) using AI software support. I am
not a Go developer normally. (And am probably not one now!) But I am a software 
dev generally, and the generated code makes sense superficially to me.

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
