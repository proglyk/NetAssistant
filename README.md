# NetAssistant — Network Debugging Assistant

<div align="center">

**A cross-platform network debugging tool built with Rust**

[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org)
[![Release](https://img.shields.io/badge/Release-latest-blue.svg)](https://github.com/sunjary/netassistant/releases/latest)
[![Downloads](https://img.shields.io/badge/Downloads-blue.svg)](https://github.com/sunjary/netassistant/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue)](https://github.com/sunjary/netassistant/releases)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

English | [Русский](README-ru.md) | [📖 Website / Docs](https://netassistant.trydo.top/en/)

</div>

---

## What it is

NetAssistant is a network debugging assistant for Windows, Linux and macOS. It opens client and
server connections, shows every message in a chat-style log, and adds the tools you need while
debugging: an auto-reply rule engine, message variables, send tasks, a stress tester and a
built-in toolbox. It is used for application protocol work, embedded device bring-up and IoT device
discovery on a LAN.

## Features

**Protocols and roles**

| Protocol | Roles | Highlights |
|---|---|---|
| TCP | client, server | decoders for raw, line-based, length-prefixed and JSON streams (fixes sticky packets), IPv4/IPv6, local address binding |
| UDP | client, server | broadcast discovery: replies from unexpected addresses are highlighted, manual "add client" in server mode |
| MQTT 3.1.1 / 5.0 | client | QoS 0/1/2, clean session, keepalive, last will, TLS (system roots / custom CA / mutual), runtime subscribe with restore after reconnect |
| UDP Session | client | secure session protocol: mutual handshake, AES-256-GCM, device push frames (see below) |

**Toolbox** — text ⇄ hex, six checksums (XOR, Sum8, LRC, CRC16-Modbus, CRC16-CCITT-FALSE, CRC32),
hashes (MD5 … SHA-512, bcrypt / Argon2id / PBKDF2), timestamp ⇄ date, JSON beautify/minify,
Base64 and URL encoding.

**Message log** — chat-style log with copy, favorites, search and selection tools; text and hex
views; JSON display formatting; export to TXT/JSON/CSV; optional real-time log file; a "keep last
N" cap to bound memory.

**Automation and testing** — a reply-rules engine (byte-level conditions, JSON paths, CIDR
source matching, nested all/any/not, first hit wins, inline test run); message variables
(`${seq}`, `${timestamp}`, `${uuid}`, `${random:min:max}`, `${rx.*}`, `${rx.json:path}`,
checksums, `${= expression }`); line-by-line send tasks and timed heartbeat tasks; LF/CRLF
suffix; TCP/UDP stress testing with QPS, latency percentiles and CSV reports.

**Interface** — light/dark theme following the system, multi-tab connections, Chinese and
English UI, hex editor, file data source (UTF-8/GBK/ANSI), keyboard shortcuts.

## UDP Session protocol

A separate connection type for devices that speak the household-IoT secure session protocol.
NetAssistant implements the client role only; the server role is not available.

**Handshake.** Four frames, all in the clear:

1. Client → `HELLO`: a random nonce.
2. Device → `CHALLENGE`: the device's own nonce plus a proof.
3. Client → `RESPONSE`: the client's proof.
4. Device → `SESSION_OK`: the session is open — or `SESSION_ERR` with a reason code.

Each proof is an HMAC-SHA256 over the shared secret and both nonces, with a context byte that
differs by direction, so a proof cannot be reflected back as the other side's answer. The client
verifies the device proof before it answers; a wrong proof ends the attempt. A handshake timeout
retries `HELLO` with the same nonce.

**Session key.** HKDF-SHA256 derives a 256-bit key from the shared secret (input keying material)
and both nonces (salt), with a fixed protocol label as info. Both sides reach the same key without
putting it on the wire.

**Encrypted traffic.** After the handshake every frame is sealed with AES-256-GCM: a unique nonce
per frame (it carries the session id, the direction and the frame sequence number), the frame
header as additional authenticated data, and a 16-byte authentication tag. Confidentiality and
integrity come from the same operation — a corrupted frame is dropped, the session stays alive.

**Ordering and replay protection.** Sequence numbers increase strictly in each direction and are
never reused; the receiver keeps the next expected number, so a replayed or skipped frame is
rejected. Encrypted frames are additionally checked against a 300-second timestamp window. The
handshake itself is not timestamp-checked: a PC clock is not a reliable time source.

**Frame types.** `DATA` carries user payload and commands, `PUSH` carries device-initiated status
snapshots and events, `CLOSE` ends the session with a reason (user disconnect, timeout, secret
rotation, error).

**What the log shows.** Decrypted payload only — ciphertext and tags are never written to the log.
Protocol stages appear as separate rows (socket, decoder, handshake, session, sender, push,
reply) with protocol field names, so a session is readable frame by frame.

**Auto-reply does not apply.** Reply rules are not evaluated on session traffic: a rule on
decrypted text would bypass GCM authentication.

**Secrets.** The shared secret never appears in logs, status hints, error messages or exported
message logs.

## Install

**Windows** — `winget install SunJary.NetAssistant` (upgrade with `winget upgrade
SunJary.NetAssistant`), or download the installer or a portable zip from the
[releases page](https://github.com/sunjary/netassistant/releases).

**Linux** — download the `.deb` and run `sudo apt install ./netassistant-*.deb`, or unpack the
tar.gz and run `./netassistant`.

**macOS** — download the `.dmg`, drag NetAssistant to Applications, open it once with a right
click ("Open") to let Gatekeeper through.

Requirements: Windows 10 1709 or newer (Windows 11 included), Linux with GTK3, macOS 10.15 or
newer.

**Build from source**

```bash
git clone https://github.com/sunjary/netassistant.git
cd netassistant
cargo build --release
```

## Tech stack

Rust 2024 · GPUI (gpui-kit) · Tokio · rumqttc (MQTT 3.1.1 / 5.0) · rustls (TLS) ·
aes-gcm / hkdf / hmac (UDP session) · serde / serde_json · rust-i18n (Chinese, English UI)

## Links

- Website and documentation: [https://netassistant.trydo.top/en/](https://netassistant.trydo.top/en/)
- Source code: [https://github.com/sunjary/netassistant](https://github.com/sunjary/netassistant)
- Issues: [https://github.com/sunjary/netassistant/issues](https://github.com/sunjary/netassistant/issues)

## License

Apache License 2.0 — see [LICENSE](LICENSE).

Thanks to [GPUI](https://github.com/zed-industries/zed),
[gpui-kit](https://crates.io/crates/gpui-kit), [Tokio](https://tokio.rs/) and
[Rust](https://www.rust-lang.org/).
