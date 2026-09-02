"""
SOCKS5 Protocol Implementation — using AnyIO byte streams
==========================================================

This module implements the SOCKS5 handshake as defined in RFC 1928.
It is the *lowest* layer of our proxy — it only knows how to parse
and produce SOCKS5 protocol messages.  It does NOT decide whether a
connection is allowed (that is the filter's job) or start relaying
data (that is the relay's job).

SOCKS5 in 60 seconds
---------------------
SOCKS5 is a *generic* TCP proxy protocol.  The client opens a TCP
connection to the proxy and says "connect me to example.com:443".
The proxy opens a *second* TCP connection to the target, then
blindly copies bytes in both directions.  Because it copies raw
bytes, HTTPS works transparently — the TLS handshake happens inside
the tunnel and the proxy never sees decrypted content.

The handshake has two phases:

  Phase 1 — GREETING (authentication negotiation)
  Phase 2 — CONNECT REQUEST (where the client wants to go)

After phase 2 succeeds, the proxy switches to "relay mode" and just
shovels bytes.

AnyIO concepts covered here
----------------------------
- ``ByteStream``  — the AnyIO abstraction for a TCP connection.
  It has two key methods:
    • ``await stream.receive(max_bytes)`` → read up to max_bytes
    • ``await stream.send(data)``        → write bytes
  When the remote side closes the connection, ``receive()`` raises
  ``anyio.EndOfStream`` (unlike raw sockets which return b"").

- ``EndOfStream`` — the clean signal that a peer hung up.

- Reading exact byte counts — ``receive()`` may return *fewer*
  bytes than requested (just like POSIX ``read``).  The helper
  ``read_exact()`` below loops until the full amount arrives.
"""

from __future__ import annotations

import enum
import ipaddress
import struct
from dataclasses import dataclass

from anyio.abc import ByteStream
from anyio import EndOfStream


# ---------------------------------------------------------------------------
# Protocol constants (RFC 1928)
# ---------------------------------------------------------------------------
# Using IntEnum so we can compare directly with byte values and still
# get readable names when printing/debugging.

SOCKS5_VERSION = 0x05


class AuthMethod(enum.IntEnum):
    """Authentication methods the client can offer."""

    NO_AUTH = 0x00  # No authentication required
    GSSAPI = 0x01  # GSSAPI (rare in practice)
    USERNAME_PASSWORD = 0x02  # RFC 1929
    NO_ACCEPTABLE = 0xFF  # Proxy rejects all offered methods


class Command(enum.IntEnum):
    """Commands the client can ask the proxy to perform."""

    CONNECT = 0x01  # Open a TCP connection to a target
    BIND = 0x02  # Listen for an incoming connection (FTP-era)
    UDP_ASSOCIATE = 0x03  # Set up UDP relay


class AddressType(enum.IntEnum):
    """How the destination address is encoded."""

    IPV4 = 0x01  # 4 bytes
    DOMAIN = 0x03  # 1-byte length + domain string
    IPV6 = 0x04  # 16 bytes


class ReplyStatus(enum.IntEnum):
    """Status codes the proxy sends back to the client."""

    SUCCEEDED = 0x00
    GENERAL_FAILURE = 0x01
    NOT_ALLOWED = 0x02  # ← we use this when a filter blocks
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


# ---------------------------------------------------------------------------
# Data container for a parsed CONNECT request
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class ConnectRequest:
    """Parsed SOCKS5 CONNECT request.

    ``frozen=True`` makes instances immutable — once we have parsed
    the request we never need to change it, and immutability prevents
    accidental bugs.

    ``slots=True`` (Python 3.10+) tells Python to use __slots__
    instead of a per-instance __dict__.  It uses slightly less memory
    and is faster for attribute access — a micro-optimization, but
    good practice for objects you create thousands of.
    """

    address_type: AddressType
    host: str  # domain name or IP string
    port: int  # 1–65535


# ---------------------------------------------------------------------------
# Low-level stream helpers
# ---------------------------------------------------------------------------

async def read_exact(stream: ByteStream, n: int) -> bytes:
    """Read exactly *n* bytes from *stream*, or raise on disconnect.

    AnyIO lesson — ``stream.receive(n)`` may return *fewer* than n
    bytes in a single call.  This is normal for any network I/O:
    data arrives in packets, and the OS gives you whatever has
    landed so far.  So we accumulate in a buffer until we have
    everything.

    If the remote side closes the connection before we collect all
    *n* bytes, ``receive()`` raises ``EndOfStream``.  We let that
    propagate — the caller will treat it as "client disconnected
    unexpectedly".
    """
    # ``bytearray`` is a mutable byte buffer — more efficient than
    # concatenating immutable ``bytes`` objects repeatedly.
    buffer = bytearray()

    while len(buffer) < n:
        remaining = n - len(buffer)
        chunk = await stream.receive(remaining)
        # AnyIO guarantees: if receive() returns without raising,
        # chunk is non-empty (at least 1 byte).
        buffer.extend(chunk)

    return bytes(buffer)


# ---------------------------------------------------------------------------
# Phase 1 — Greeting / auth negotiation
# ---------------------------------------------------------------------------

async def negotiate_auth(client: ByteStream) -> bool:
    """Perform the SOCKS5 greeting handshake.

    Wire format — client sends:
    ┌─────────┬──────────┬────────────────┐
    │ VER (1) │ NMET (1) │ METHODS (NMET) │
    └─────────┴──────────┴────────────────┘

    VER   = 0x05 (SOCKS version 5)
    NMET  = number of auth methods the client supports
    METHODS = list of method codes (each 1 byte)

    We respond with:
    ┌─────────┬────────────┐
    │ VER (1) │ METHOD (1) │
    └─────────┴────────────┘

    If the client supports NO_AUTH (0x00), we pick that.
    Otherwise we respond with NO_ACCEPTABLE (0xFF) and return False.

    Returns True if negotiation succeeded.
    """
    # Read the 2-byte header: version + number of methods
    header = await read_exact(client, 2)

    # ``struct.unpack`` decodes raw bytes into Python values.
    #   "!" = network byte order (big-endian)
    #   "B" = unsigned byte (1 byte → int 0..255)
    #   "BB" = two unsigned bytes
    version, n_methods = struct.unpack("!BB", header)

    if version != SOCKS5_VERSION:
        # Not a SOCKS5 client — nothing we can do.
        return False

    # Read the method list (one byte per method)
    methods_raw = await read_exact(client, n_methods)

    # Check if NO_AUTH (0x00) is among the offered methods.
    # We convert to a set for O(1) lookup, though with ≤255
    # methods this barely matters — it just reads nicely.
    offered = set(methods_raw)

    if AuthMethod.NO_AUTH in offered:
        # Accept: "I pick NO_AUTH"
        await client.send(
            struct.pack("!BB", SOCKS5_VERSION, AuthMethod.NO_AUTH)
        )
        return True
    else:
        # Reject: "none of your methods work for me"
        await client.send(
            struct.pack("!BB", SOCKS5_VERSION, AuthMethod.NO_ACCEPTABLE)
        )
        return False


# ---------------------------------------------------------------------------
# Phase 2 — CONNECT request
# ---------------------------------------------------------------------------

async def read_connect_request(client: ByteStream) -> ConnectRequest | None:
    """Read and parse a SOCKS5 CONNECT request.

    Wire format — client sends:
    ┌─────────┬─────────┬─────────┬──────────┬──────────────┬──────────┐
    │ VER (1) │ CMD (1) │ RSV (1) │ ATYP (1) │ DST.ADDR (…) │ PORT (2) │
    └─────────┴─────────┴─────────┴──────────┴──────────────┴──────────┘

    VER      = 0x05
    CMD      = 0x01 for CONNECT (the only one we support)
    RSV      = reserved, must be 0x00
    ATYP     = address type:
                 0x01 → IPv4 (4 bytes follow)
                 0x03 → domain name (1-byte length, then that many ASCII bytes)
                 0x04 → IPv6 (16 bytes follow)
    DST.ADDR = the address bytes (variable length depending on ATYP)
    PORT     = 2 bytes, big-endian unsigned short

    Returns a ConnectRequest on success, or None if the command is
    unsupported (in which case we've already sent an error reply).
    """
    header = await read_exact(client, 4)
    version, cmd, _reserved, atyp = struct.unpack("!BBBB", header)

    if version != SOCKS5_VERSION:
        return None

    # We only support CONNECT — BIND and UDP_ASSOCIATE are niche.
    if cmd != Command.CONNECT:
        await send_reply(client, ReplyStatus.COMMAND_NOT_SUPPORTED)
        return None

    # --- Parse the destination address ---
    try:
        address_type = AddressType(atyp)
    except ValueError:
        await send_reply(client, ReplyStatus.ADDRESS_TYPE_NOT_SUPPORTED)
        return None

    if address_type == AddressType.IPV4:
        raw = await read_exact(client, 4)
        host = str(ipaddress.IPv4Address(raw))

    elif address_type == AddressType.DOMAIN:
        # Length-prefixed ASCII domain name.
        # NOTE: when the client uses socks5h:// (the "h" variant),
        # DNS resolution is delegated to the proxy, so we receive
        # domain names here instead of IPs.  This is what lets us
        # display and filter by domain name in the TUI.
        length_byte = await read_exact(client, 1)
        length = length_byte[0]  # single byte → int
        if length == 0:
            raise ValueError("SOCKS5 domain name length is 0")
        host = (await read_exact(client, length)).decode("ascii")

    elif address_type == AddressType.IPV6:
        raw = await read_exact(client, 16)
        host = str(ipaddress.IPv6Address(raw))

    else:
        await send_reply(client, ReplyStatus.ADDRESS_TYPE_NOT_SUPPORTED)
        return None

    # --- Parse the port (always 2 bytes, big-endian) ---
    port_bytes = await read_exact(client, 2)
    port = struct.unpack("!H", port_bytes)[0]
    if port == 0:
        raise ValueError("SOCKS5 CONNECT port 0 is not valid")

    return ConnectRequest(address_type, host, port)


# ---------------------------------------------------------------------------
# Reply helper
# ---------------------------------------------------------------------------

async def send_reply(
    client: ByteStream,
    status: ReplyStatus,
    bind_host: str = "0.0.0.0",
    bind_port: int = 0,
) -> None:
    """Send a SOCKS5 reply to the client.

    Wire format (mirrors the request):
    ┌─────────┬─────────┬─────────┬──────────┬──────────────┬──────────┐
    │ VER (1) │ REP (1) │ RSV (1) │ ATYP (1) │ BND.ADDR (4) │ PORT (2) │
    └─────────┴─────────┴─────────┴──────────┴──────────────┴──────────┘

    BND.ADDR and BND.PORT tell the client which local address the
    proxy is using for the outgoing connection.  For our dev proxy
    we just send 0.0.0.0:0 — clients rarely use these fields.
    """
    # We always report the bind address as IPv4 for simplicity.
    addr_parts = bind_host.split(".")
    if len(addr_parts) == 4 and all(p.isdigit() for p in addr_parts):
        try:
            addr_bytes = bytes(int(p) for p in addr_parts)
        except ValueError:
            addr_bytes = b"\x00\x00\x00\x00"
    else:
        addr_bytes = b"\x00\x00\x00\x00"

    reply = struct.pack(
        "!BBBB",
        SOCKS5_VERSION,
        status,
        0x00,  # reserved
        AddressType.IPV4,
    )
    reply += addr_bytes
    reply += struct.pack("!H", bind_port)

    await client.send(reply)
