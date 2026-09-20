"""ArrowBridge companion: a small local HTTP checkpoint between a model running on your own
machine and the phone or client asking it questions.

It forwards one chat turn to a model server on this machine (llama.cpp on 127.0.0.1:8080, or
Ollama on 127.0.0.1:11434), then removes any telephone number the model invented before the
reply leaves this process. Nothing in this file talks to the internet, and no cloud SDK is
imported.

Run it:

    set ARROWBRIDGE_UPSTREAM_MODEL=<the model name your local server loads>
    python companion_server.py

Talk to it (the server logs a pairing key at startup if you never set ARROWBRIDGE_PAIR_KEY):

    curl.exe -s -X POST http://127.0.0.1:8788/chat -H "Content-Type: application/json" ^
        -H "X-ArrowBridge-Pair: <key from the startup log>" -d "{\\"message\\": \\"hello\\"}"

Reach it from a phone on the same network by setting ARROWBRIDGE_BIND to the ONE address of
the interface the phone shares with this machine (the README's example is 192.0.2.10; yours
differs). 0.0.0.0 is refused at startup; see the bind section below for why.

PAIRING, two shapes:

  1. A shared key. ARROWBRIDGE_PAIR_KEY (or the one generated at startup) is sent on every
     request as `X-ArrowBridge-Pair: <key>` or as a bearer token, compared in constant time.
     An unpaired caller gets 404, never 401, so a scanner learns nothing about what is here.

  2. Numeric comparison, for a client that implements it. This repo ships the server side and a
     test driver (test_pairing_handshake.py), not a phone app. The owner opens a short pairing
     window at the machine (POST /pair-open, loopback only). Phone and companion then run an
     X25519 key agreement in two rounds, mutual commit-then-reveal, with neither side revealing
     its nonce before both have committed to one:

       Round one (POST /pair-start): the phone sends its ephemeral public key AND a commitment
       H(phone_nonce || phone_pubkey), never the nonce. The companion answers with its own public
       key and its own commitment H(companion_nonce || companion_pubkey), also never its nonce.
       No four-digit code exists as an observable quantity yet.

       Round two (POST /pair-reveal): the phone reveals phone_nonce. The companion checks it
       against the round-one commitment; only on a match does it reveal its own nonce. THE PHONE
       MUST PERFORM THE SAME CHECK on what this response reveals (H(companion_nonce ||
       companion_pubkey) == the round-one companion_commitment). This server can only prove it
       is not lying about its own side; the phone's check is what closes the loop.

     Both sides then derive the same four digits from the shared secret, both public keys and
     both nonces (fixed order: phone_nonce then companion_nonce, see _derive_pairing_material).
     The owner reads the digits on the machine's own screen (the log, or GET /pair-status on
     loopback) and confirms at the machine (POST /pair-confirm, loopback only). The phone's
     human taps "Yes, it matches", which sends POST /pair-finish with an HMAC proof over the
     handshake id under the session key. Only with BOTH confirmations and a verified proof does
     the companion mint a per-phone credential and return it encrypted under the session key.
     Nothing is typed or pasted; the human only ever sees four digits.

     Why mutual commit-then-reveal and not a one-sided reveal: a companion that reveals its nonce
     immediately lets an attacker in the companion role grind (private key, nonce) pairs
     offline until the four digits match a target the human will confirm. Committing before
     either side has seen the other's nonce removes exactly the freedom grinding depends on.
     See _pairing_attacks.py for the attack run against this protocol on every test run.

     Why a new per-phone credential and not the shared key: one phone's credential can be
     revoked (drop it from _phone_credentials) without rotating the key every other paired
     phone holds. Credentials, session tokens and a generated key are all in memory only; a
     restart means re-pairing.

ponytail: no streaming from the upstream. One buffered request and response per turn, because
the telephone guard needs the whole reply before any of it can leave. The /v1/messages route
still answers a valid SSE body when asked to stream; it delivers the whole reply in one delta.
ponytail: no per-caller identity beyond the credentials above. Every paired caller is trusted
equally.
"""

import base64
import binascii
import hmac
import html
import http.server
import json
import logging
import os
import secrets
import socketserver
import ssl
import string
import sys
import threading
import time
import urllib.parse
import urllib.request

import tel_guard

# Optional safety hooks. This repo ships none. If a module named `arrowbridge_pack` is importable
# it may provide: floor_text() -> str, a footer appended to every reply and every error body;
# redact(text) -> str, a second pass after the telephone guard; ALLOWED_NUMBERS, telephone
# numbers the footer itself states, which the guard then lets through. With no such module,
# floor_text() is "" and no second pass runs. The telephone guard below runs either way.
try:
    import arrowbridge_pack as _pack
except ImportError:
    _pack = None
PACK_ACTIVE = _pack is not None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("companion")

PORT = int(os.environ.get("ARROWBRIDGE_PORT", "8788"))
UPSTREAM_URL = os.environ.get("ARROWBRIDGE_UPSTREAM_URL", "http://127.0.0.1:8080").rstrip("/")
UPSTREAM_MODEL = os.environ.get("ARROWBRIDGE_UPSTREAM_MODEL", "")
# Sent as a bearer token to the upstream when non-empty. Not a secret: anything that can reach a
# loopback-bound model server has already reached the machine. Some local servers want some
# Authorization header present; set it empty for one that wants none (Ollama accepts none).
UPSTREAM_KEY = os.environ.get("ARROWBRIDGE_UPSTREAM_KEY", "local")

# ---------------------------------------------------------------- the bind, and its boundary
# On 127.0.0.1 only this machine can reach the companion. Binding a LAN address is the whole
# point of the phone story, and it is also the one change that deletes the loopback trust
# boundary: anything on the network can now connect. So a pairing key is required on every bind,
# and the bind must be ONE specific interface. 0.0.0.0 additionally listens on every other
# interface this machine has, present and future (a VPN, a tethered connection, a network it
# joins later) for zero benefit over naming the one a phone on this network actually uses.
BIND_HOST = os.environ.get("ARROWBRIDGE_BIND", "127.0.0.1").strip() or "127.0.0.1"
if BIND_HOST in ("0.0.0.0", "::"):
    sys.stderr.write(
        "ArrowBridge REFUSES TO START.\n"
        "  ARROWBRIDGE_BIND=%s listens on every interface this machine has. Name the one\n"
        "  address of the interface your phone shares with this machine instead, for example\n"
        "  ARROWBRIDGE_BIND=192.0.2.10 (find yours with ipconfig, ifconfig or ip addr).\n"
        % BIND_HOST)
    raise SystemExit(2)
LAN_EXPOSED = BIND_HOST not in ("127.0.0.1", "localhost", "::1")
PAIR_KEY = os.environ.get("ARROWBRIDGE_PAIR_KEY", "").strip()

# Fail closed by default. A key that is only enforced when someone remembers to configure one is
# not a control; unauthenticated local model servers on the open internet are a measured,
# recurring finding, and they get there because auth is opt-in. There is no "no key needed"
# state here: if nobody set one, a fresh key is generated for this run and printed once at
# startup. Set ARROWBRIDGE_PAIR_KEY for a key that survives a restart.
if not PAIR_KEY:
    PAIR_KEY = secrets.token_urlsafe(32)
    PAIR_KEY_WAS_GENERATED = True
else:
    PAIR_KEY_WAS_GENERATED = False

# ------------------------------------------------------------ session tokens
# POST /pair-session exchanges the raw key for a short-lived token, so a client that keeps its
# copy of the key in locked storage does not have to unlock it on every request. A dict behind a
# lock: several phones may share one key, and ThreadingTCPServer serves requests on separate
# threads. Wiped on restart along with PAIR_KEY.
SESSION_TOKEN_TTL_SECONDS = 60 * 60
_session_tokens = {}
_session_tokens_lock = threading.Lock()


def _mint_session_token():
    token = secrets.token_urlsafe(32)
    with _session_tokens_lock:
        _session_tokens[token] = time.monotonic() + SESSION_TOKEN_TTL_SECONDS
    return token


def _session_token_valid(token):
    """True when `token` was minted here and has not yet expired. Expired entries are dropped on
    lookup. ponytail: no background sweep thread; add one if this ever holds enough dead entries
    to matter, which a single-owner companion never will."""
    if not token:
        return False
    now = time.monotonic()
    with _session_tokens_lock:
        expiry = _session_tokens.get(token)
        if expiry is None:
            return False
        if expiry < now:
            del _session_tokens[token]
            return False
        return True

# ---------------------------------------------------------------- TLS, optional
# On top of the pairing key, never instead of it: the key authenticates the caller, TLS only
# encrypts the wire and proves this device to the caller. Off unless both variables point at a
# PEM certificate and key. Certificates expire on a wall clock, and a machine offline long enough
# for its clock to drift can refuse its own certificate, so the break-glass is not a code path:
# unset both variables and restart, which drops back to pairing-key-only mode, never a lockout.
TLS_CERT = os.environ.get("ARROWBRIDGE_TLS_CERT", "").strip()
TLS_KEY = os.environ.get("ARROWBRIDGE_TLS_KEY", "").strip()
TLS_ENABLED = bool(TLS_CERT and TLS_KEY)


class _TLSThreadingTCPServer(socketserver.ThreadingTCPServer):
    """Wraps each accepted connection in TLS before the handler sees it. Stdlib only.

    A handshake failure must drop one connection, never the process: a phone retrying a stale
    connection, a port scanner, or plain HTTP sent at an HTTPS port all raise here, inside
    serve_forever's accept loop. Logged at WARNING, not ERROR: routine, not a sign anything here
    is broken."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
        self._tls_context = ctx

    def get_request(self):
        sock, addr = super().get_request()
        try:
            return self._tls_context.wrap_socket(sock, server_side=True), addr
        except (ssl.SSLError, OSError) as exc:
            logger.warning("TLS handshake failed from %s: %s", addr, type(exc).__name__)
            try:
                sock.close()
            except OSError:
                pass
            raise


def _presented_credential(headers):
    """The caller's credential from either header this file accepts one in: `X-ArrowBridge-Pair`
    or a bearer token. One place, shared by both checks below."""
    presented = (headers.get("X-ArrowBridge-Pair") or "").strip()
    if not presented:
        auth = (headers.get("Authorization") or "").strip()
        if auth.lower().startswith("bearer "):
            presented = auth[7:].strip()
    return presented


def _raw_key_ok(headers):
    """True only when the caller presents the ACTUAL PAIR_KEY, never a session token, even a
    valid one. Constant-time compare.

    This exists because /pair-session must not accept a session token: a token holder could
    otherwise mint itself a fresh token every 59 minutes, and a captured token would never
    actually expire. A route that hands out something needs a stricter check than the shared
    one, not the shared one."""
    presented = _presented_credential(headers)
    return bool(presented) and hmac.compare_digest(presented, PAIR_KEY)


def _pairing_ok(headers):
    """True when this caller may be served. Accepts any of three credential kinds in the same
    header, so the caller never needs to know which it holds: the raw PAIR_KEY, a session token
    from /pair-session, or a per-phone credential from /pair-finish. Cheapest check first."""
    presented = _presented_credential(headers)
    if not presented:
        return False
    if hmac.compare_digest(presented, PAIR_KEY):
        return True
    if _session_token_valid(presented):
        return True
    return _phone_credential_ok(presented)


# Headers a reverse proxy adds when relaying to a loopback backend. A request carrying any of
# them reached loopback through a proxy, so the peer address proves nothing about who sent it.
# A proxy that adds none of these cannot be detected here; the README says not to run one.
_PROXY_HEADERS = ("X-Forwarded-For", "Forwarded")


def _pair_info_ok(peer_ip, headers):
    """True when a caller is genuinely the owner's own machine: a loopback peer address AND no
    proxy header. Used for every owner-only route (/pair-info, /pair, /pair-open, /pair-status,
    /pair-confirm, /pair-cancel). A pure function of (peer_ip, headers) so it is unit-testable
    without a socket."""
    if peer_ip not in ("127.0.0.1", "::1"):
        return False
    return not any(headers.get(h) for h in _PROXY_HEADERS)


# An alias, not a copy, so the two owner-only checks can never drift apart.
_local_owner_ok = _pair_info_ok


# =============================================================== pairing handshake
# /pair-start, /pair-reveal and /pair-finish are reachable with NO credential (the phone has none
# yet; that is the point of pairing). The only thing between them and anyone on the LAN is that
# they exist only inside a short window the owner opened by hand, at the machine, which closes
# itself the instant it is used or times out. Outside the window every pairing route answers 404.
PAIRING_WINDOW_SECONDS = 180

_pairing_lock = threading.Lock()
_pairing_window = {"open": False, "expires_at": None}
_active_handshake = None  # dict or None; exactly one handshake at a time, see _pairing_lock

# Long-lived, per-phone pairing credentials. In memory only, like PAIR_KEY.
_phone_credentials = {}
_phone_credentials_lock = threading.Lock()


def _pairing_window_is_open():
    """True only while a window the owner opened is still live. Expiry is checked on read, not
    by a timer thread."""
    with _pairing_lock:
        if not _pairing_window["open"]:
            return False
        if _pairing_window["expires_at"] is None or time.monotonic() >= _pairing_window["expires_at"]:
            _pairing_window["open"] = False
            _pairing_window["expires_at"] = None
            global _active_handshake
            _active_handshake = None
            return False
        return True


def _open_pairing_window():
    """Opens a fresh window, discarding any prior handshake. Only /pair-open calls this."""
    global _active_handshake
    with _pairing_lock:
        _pairing_window["open"] = True
        _pairing_window["expires_at"] = time.monotonic() + PAIRING_WINDOW_SECONDS
        _active_handshake = None
    logger.info("pairing window opened (%ds)", PAIRING_WINDOW_SECONDS)


def _close_pairing_window_locked():
    """As `_close_pairing_window`, for a caller that ALREADY holds `_pairing_lock`.
    `threading.Lock` is not reentrant; calling the locking wrapper from inside a `with
    _pairing_lock:` block deadlocks the process."""
    global _active_handshake
    _pairing_window["open"] = False
    _pairing_window["expires_at"] = None
    _active_handshake = None


def _close_pairing_window():
    """Closes the window and invalidates whatever handshake was in progress: on success, on a
    definitive failure, and lazily on timeout."""
    with _pairing_lock:
        _close_pairing_window_locked()


def _commitment(nonce, pubkey):
    """H(nonce || pubkey), SHA-256: the commitment each side publishes before either nonce is
    revealed."""
    import hashlib
    return hashlib.sha256(nonce + pubkey).digest()


def _derive_pairing_material(shared_secret, phone_nonce, companion_nonce, companion_pub, phone_pub):
    """HKDF-derives the session key and the four-digit code from the ECDH shared secret, both raw
    public keys and both nonces. Two independent HKDF outputs with different `info` labels, never
    one value truncated into the other, so learning the short code can never help recover the
    session key. Nonce order in the salt is fixed (phone, then companion) so the two sides cannot
    derive different material by disagreeing on order."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    context = companion_pub + phone_pub
    salt = phone_nonce + companion_nonce
    session_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=b"arrowbridge-pairing-session-key|" + context,
    ).derive(shared_secret)
    code_material = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        info=b"arrowbridge-pairing-code|" + context,
    ).derive(shared_secret)
    code = "%04d" % (int.from_bytes(code_material[:4], "big") % 10000)
    return session_key, code


def _mint_phone_credential(handshake_id):
    """A fresh per-phone credential: an independent random token, not derived from the handshake
    material, so nothing about the session key is recoverable from it and it can be revoked on
    its own."""
    token = "pc_" + secrets.token_urlsafe(32)
    with _phone_credentials_lock:
        _phone_credentials[token] = {"created_at": time.monotonic(), "handshake_id": handshake_id}
    return token


def _phone_credential_ok(presented):
    if not presented:
        return False
    with _phone_credentials_lock:
        return presented in _phone_credentials


def _parse_model_map(raw):
    """ARROWBRIDGE_MODEL_MAP: comma-separated `NAME=upstream_model[@url]` entries, the
    server-side allow list a request's `model` field is resolved against. The caller selects a
    NAME from this closed, operator-configured map, never a URL or upstream model id directly, so
    a request can never point this companion at a server the operator did not configure. `@url`
    is optional per entry and defaults to ARROWBRIDGE_UPSTREAM_URL."""
    entries = {}
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        name, _, rest = part.partition("=")
        name = name.strip()
        rest = rest.strip() or name
        model_id, _, url = rest.partition("@")
        entries[name] = (model_id.strip(), (url.strip() or UPSTREAM_URL).rstrip("/"))
    return entries


MODEL_MAP = _parse_model_map(os.environ.get("ARROWBRIDGE_MODEL_MAP", ""))


def resolve_model(requested_name):
    """Resolve a request's `model` field against MODEL_MAP. The model NAME is the only thing the
    request may influence. An absent or unknown name never fails the request (the caller is
    mid-conversation); it falls back to the configured default and logs that it did, so a typo
    reads as a fallback in the log rather than a silent identical reply."""
    if requested_name and requested_name in MODEL_MAP:
        return MODEL_MAP[requested_name]
    if requested_name:
        logger.warning("unknown model %r requested; falling back to default %r",
                        requested_name, UPSTREAM_MODEL or "(unset)")
    return (UPSTREAM_MODEL, UPSTREAM_URL)


_last_served_model = {"id": None}


def note_model_switch(model_id):
    """Logs when the resolved model differs from the last one served. A local server usually
    holds one model at a time, so a switch costs a reload and the first reply after it is slow."""
    previous = _last_served_model["id"]
    if previous not in (None, model_id):
        logger.info("model switch: %s -> %s (reload in progress, first reply may be slow)",
                     previous, model_id)
    _last_served_model["id"] = model_id


# With no safety module present only the universal emergency number survives the guard.
TEL_ALLOWED = tel_guard.UNIVERSAL_EMERGENCY | frozenset(getattr(_pack, "ALLOWED_NUMBERS", ()))

# The system prompt is the operator's, read from a file, or nothing at all. Never from a request:
# /chat drops a `system` role in the history it is sent and /v1/messages ignores the caller's
# `system` field, so a client cannot rewrite the instructions the operator runs their model under.
# A configured file that cannot be read fails startup rather than silently running without it.
_PROMPT_PATH = os.environ.get("ARROWBRIDGE_SYSTEM_PROMPT_FILE", "").strip()
SYSTEM_PROMPT = ""
if _PROMPT_PATH:
    with open(_PROMPT_PATH, encoding="utf-8") as _fh:
        SYSTEM_PROMPT = _fh.read().strip()


def floor_text():
    """The safety module's footer, or "" when none is present. Not conditioned on anything the
    model said: appended to every reply and every error body, or to none."""
    return _pack.floor_text() if PACK_ACTIVE else ""


def _with_floor(explanation):
    """An error explanation with the footer appended when a safety module is present."""
    tail = floor_text()
    return explanation + ("\n\n" + tail if tail else "")


def compose_reply(model_text):
    """What the user sees for one turn: the model's prose with any telephone number not on the
    allow list removed, the safety module's second pass if one is present, then its footer."""
    cleaned, _offenders = tel_guard.redact(model_text or "", TEL_ALLOWED)
    if PACK_ACTIVE:
        cleaned = _pack.redact(cleaned)
    tail = floor_text()
    parts = [p for p in (cleaned.strip(), tail) if p]
    return "\n\n".join(parts)


class NotConfigured(Exception):
    """Raised when the companion itself is not set up, as opposed to the upstream being
    unreachable, so the HTTP layer can tell the operator which one it is."""


def _clean_history(history):
    """Only `user`/`assistant` turns pass through. A `system` role in the request body would sit
    after the operator's own system prompt and could argue with it. The system prompt comes from
    this file only, never from a request field."""
    out = []
    for turn in history or []:
        if isinstance(turn, dict) and turn.get("role") in ("user", "assistant") and turn.get("content"):
            out.append({"role": turn["role"], "content": turn["content"]})
    return out


def call_upstream(user_message, history=None):
    """POST one turn to the upstream's OpenAI-compatible /v1/chat/completions. Raises on any
    failure or timeout and never substitutes a different backend: a silent fallback would mean
    the user gets a different model without knowing."""
    if not UPSTREAM_MODEL:
        raise NotConfigured("ARROWBRIDGE_UPSTREAM_MODEL is not set")
    messages = []
    if SYSTEM_PROMPT:
        messages.append({"role": "system", "content": SYSTEM_PROMPT})
    messages.extend(_clean_history(history))
    messages.append({"role": "user", "content": user_message})
    headers = {"Content-Type": "application/json"}
    if UPSTREAM_KEY:
        headers["Authorization"] = "Bearer " + UPSTREAM_KEY
    req = urllib.request.Request(
        UPSTREAM_URL + "/v1/chat/completions",
        data=json.dumps({"model": UPSTREAM_MODEL, "messages": messages}).encode("utf-8"),
        headers=headers,
        method="POST")
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["choices"][0]["message"]["content"]


# /v1/messages is proxied, not translated: llama.cpp's server implements the Anthropic Messages
# wire shape itself (POST /v1/messages and /v1/messages/count_tokens). An upstream that does not
# (Ollama) will fail this route; /chat works with either.
_STOP_REASON_DEFAULT = "end_turn"

# ponytail: one chat turn is kilobytes. Anything past a MiB is refused before authentication.
MAX_BODY_BYTES = 1 << 20


def call_upstream_messages(messages, max_tokens=None, model_id=None, url=None):
    """POST to the upstream's own /v1/messages endpoint.

    `model_id`/`url` come from `resolve_model`'s allow-list lookup, never straight from the
    request. Two things are deliberately NOT passed through from the caller: `system` (the
    operator's prompt is the only one, see SYSTEM_PROMPT) and any role other than user/assistant
    in `messages` (`_clean_history`, the same filter /chat uses).

    Always forwards `"stream": False` even when the caller asked to stream: the telephone guard
    runs on the complete reply, and a number split across two deltas would reach the caller
    before the guard could see the whole string. The caller still gets a valid SSE body when it
    asked for one (see _build_sse_body).

    Returns a dict: text, stop_reason, usage, model."""
    model_id = model_id or UPSTREAM_MODEL
    url = url or UPSTREAM_URL
    if not model_id:
        raise NotConfigured("ARROWBRIDGE_UPSTREAM_MODEL is not set")
    payload = {
        "model": model_id,
        "messages": _clean_history(messages),
        "max_tokens": max_tokens or 1024,
        "stream": False,
    }
    if SYSTEM_PROMPT:
        payload["system"] = SYSTEM_PROMPT
    headers = {"Content-Type": "application/json"}
    if UPSTREAM_KEY:
        headers["Authorization"] = "Bearer " + UPSTREAM_KEY
    req = urllib.request.Request(
        url + "/v1/messages",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST")
    # 240s: a cold model load on the upstream can take minutes, and a timeout here reads to the
    # user as a dead companion, not a slow model.
    with urllib.request.urlopen(req, timeout=240) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    text = "".join(
        block.get("text", "") for block in data.get("content", []) if block.get("type") == "text")
    return {
        "text": text,
        "stop_reason": data.get("stop_reason") or _STOP_REASON_DEFAULT,
        "usage": data.get("usage") or {},
        "model": model_id,
    }


def _anthropic_message_payload(text, stop_reason=_STOP_REASON_DEFAULT, usage=None, model=None):
    """The Messages response envelope, filled with `text` (already composed by every caller).
    One place both the buffered and the streamed sender build this from."""
    return {
        "id": "msg_local",
        "type": "message",
        "role": "assistant",
        "content": [{"type": "text", "text": text}],
        "model": model or UPSTREAM_MODEL or "local",
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": usage or {"input_tokens": 0, "output_tokens": 0},
    }


def _sse_event(event_type, data):
    return "event: %s\ndata: %s\n\n" % (event_type, json.dumps(data))


def _build_sse_body(text, stop_reason, usage, model=None):
    """A complete, valid Messages streaming response, built from a reply this process already
    has in full. What is not real: per-token timing. The whole composed reply arrives as one
    `content_block_delta`, because the telephone guard needs the complete text before any of it
    can leave. A client parsing this sees a structurally normal stream whose one delta arrives
    immediately."""
    usage = usage or {}
    start_message = _anthropic_message_payload("", usage=dict(usage, output_tokens=0), model=model)
    start_message["content"] = []
    start_message["stop_reason"] = None
    parts = [
        _sse_event("message_start", {"type": "message_start", "message": start_message}),
        _sse_event("content_block_start", {
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        }),
        _sse_event("content_block_delta", {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": text},
        }),
        _sse_event("content_block_stop", {"type": "content_block_stop", "index": 0}),
        _sse_event("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": {"output_tokens": usage.get("output_tokens", 0)},
        }),
        _sse_event("message_stop", {"type": "message_stop"}),
    ]
    return "".join(parts)


# ------------------------------------------------------------ /pair page (machine side)
# The phone finds the machine by scanning a QR on THIS screen. The QR carries only the
# companion's non-secret LAN address and a display name, the same two facts discovery.py already
# broadcasts in cleartext. Never a key.
def _pairing_address():
    """The address a phone on the LAN reaches this companion at, or "" when bound to loopback
    (there is nothing a phone could reach in that case, so the page says so instead of showing a
    code with nothing real in it)."""
    if not LAN_EXPOSED:
        return ""
    return "%s://%s:%d" % ("https" if TLS_ENABLED else "http", BIND_HOST, PORT)


def _pairing_qr_payload(address, name):
    """The exact, non-secret JSON object the QR carries: address and name, nothing else. A pure
    function of its two arguments so the payload the QR encodes and the payload a test asserts on
    are provably the same value."""
    return {"address": address, "name": name}


def _pairing_qr_svg_data_uri(payload):
    """Server-generated QR encoding `payload` as compact JSON. SVG via segno: no image codec.
    Returned as a data: URI so the page stays one self-contained file."""
    import io
    import segno
    text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    qr = segno.make(text, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="svg", scale=6, border=2, dark="#10231A", light="#FFFFFF")
    return "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode("ascii")


_PAIR_PAGE_HTML_TEMPLATE = string.Template("""<!doctype html>
<html lang="en" data-theme="white" data-mode="light">
<head>
<script>(function(){try{if(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)document.documentElement.setAttribute('data-mode','dark');}catch(e){}})();</script>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>ArrowBridge - companion pairing (machine side)</title>
<style>
:root{
  --fs-display:40px; --fs-heading:28px; --fs-title:20px;
  --fs-body:17px;    --fs-ui:15px;      --fs-small:14px; --fs-label:13px;
  --lh-display:48px; --lh-heading:36px; --lh-title:28px;
  --lh-body:26px;    --lh-ui:22px;      --lh-small:20px; --lh-label:16px;
  --fw-reg:400; --fw-med:500; --fw-semi:600; --fw-bold:700;
  --sp-1:4px; --sp-2:8px; --sp-3:12px; --sp-4:16px;
  --sp-6:24px; --sp-8:32px; --sp-12:48px; --sp-16:64px;
  --r-sm:8px; --r-md:12px; --r-lg:20px; --r-xl:28px; --r-pill:999px;
  --target:48px; --target-sm:32px;
  --focus-ring:3px; --focus-gap:2px;
  --font:"Public Sans","Inter","SF Pro Text",system-ui,-apple-system,"Segoe UI",sans-serif;
  --font-mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;
}
[data-theme="white"][data-mode="light"]{
  --surface:#FFFFFF; --surface-raised:#EDF3EE; --surface-sunken:#F7FAF8;
  --border:#CBD8CE; --border-strong:#6E7F74;
  --ink:#10231A; --ink-muted:#55665C; --ink-on-action:#FFFFFF;
  --action:#14532D; --action-hover:#0E3D20; --action-soft:#DCE9DF;
  --focus:#14532D;
  --danger:#C8102E; --shadow:rgba(16,35,26,.12);
}
[data-theme="white"][data-mode="dark"]{
  --surface:#0B0B0C; --surface-raised:#17181A; --surface-sunken:#070708;
  --border:#2A2C2F; --border-strong:#878B91;
  --ink:#ECEDEE; --ink-muted:#A2A6AC; --ink-on-action:#111214;
  --action:#EDEEF0; --action-hover:#FFFFFF; --action-soft:#1E2023;
  --focus:#FFFFFF;
  --danger:#FF6A7E; --shadow:rgba(0,0,0,.6);
}
*,*::before,*::after{box-sizing:border-box}
html,body{height:100%;margin:0}
body{font-family:var(--font);font-size:var(--fs-body);line-height:var(--lh-body);
  color:var(--ink);background:var(--surface-sunken);letter-spacing:-.011em;
  -webkit-font-smoothing:antialiased}
button{font:inherit;color:inherit}
:focus-visible{outline:var(--focus-ring) solid var(--focus);outline-offset:var(--focus-gap);border-radius:var(--r-sm)}
.gallery{display:grid;gap:var(--sp-12);max-width:520px;margin:0 auto;padding:var(--sp-12) var(--sp-4)}
.machine-window{background:var(--surface);border:1px solid var(--border-strong);
  border-radius:var(--r-lg);box-shadow:0 14px 40px var(--shadow);overflow:hidden}
.machine-window__bar{display:flex;align-items:center;gap:var(--sp-2);
  padding:var(--sp-2) var(--sp-4);background:var(--surface-raised);border-bottom:1px solid var(--border)}
.machine-window__dot{width:10px;height:10px;border-radius:var(--r-pill);background:var(--border-strong);flex:none}
.machine-window__t{font-size:var(--fs-label);font-weight:var(--fw-semi);color:var(--ink-muted)}
.machine-window__body{padding:var(--sp-12) var(--sp-8);display:grid;gap:22px;justify-items:center;text-align:center}
.idle-row{display:flex;align-items:center;gap:var(--sp-3);color:var(--ink-muted);font-size:var(--fs-small)}
.idle-dot{width:8px;height:8px;border-radius:var(--r-pill);background:var(--action);flex:none}
h2{margin:0;font-size:var(--fs-title);line-height:var(--lh-title);font-weight:var(--fw-semi)}
.p-muted{margin:0;max-width:36ch;color:var(--ink-muted);font-size:var(--fs-small);line-height:22px}
.matchcode{display:grid;gap:10px;justify-items:center;text-align:center}
.matchcode__code{font-family:var(--font-mono);font-size:clamp(40px,10vw,56px);font-weight:var(--fw-bold);
  letter-spacing:.1em;color:var(--ink)}
.matchcode__hint{margin:0;max-width:38ch;color:var(--ink-muted);font-size:var(--fs-small)}
.matchcode__acts{display:flex;gap:var(--sp-3);width:100%;max-width:360px;margin-top:4px}
.matchcode__acts .btn{flex:1}
.keypress-hint{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;
  gap:6px 10px;padding:var(--sp-3) var(--sp-6);
  background:var(--surface-sunken);border:1px solid var(--border);border-radius:var(--r-pill);
  font-size:var(--fs-small);line-height:22px;color:var(--ink-muted)}
kbd{font-family:var(--font-mono);font-size:var(--fs-label);font-weight:var(--fw-bold);
  padding:2px var(--sp-2);border:1px solid var(--border-strong);border-radius:var(--r-sm);
  background:var(--surface);color:var(--ink)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:var(--sp-2);
  min-height:var(--target);padding:0 var(--sp-6);border-radius:var(--r-pill);cursor:pointer;
  font-size:var(--fs-ui);font-weight:var(--fw-semi);background:var(--action);color:var(--ink-on-action);
  border:1px solid var(--action)}
.btn--ghost{background:var(--surface);color:var(--ink);border:1px solid var(--border-strong)}
.truth{display:grid;gap:10px;padding:var(--sp-4) var(--sp-6);width:100%;margin-top:6px;
  background:var(--surface-raised);border:1px solid var(--border-strong);border-radius:var(--r-md);
  text-align:left}
.truth__h{margin:0;font-size:var(--fs-label);font-weight:var(--fw-bold)}
.truth__p{margin:0;font-size:var(--fs-label);line-height:19px;color:var(--ink-muted)}
.pending-row{display:flex;align-items:center;gap:var(--sp-2);color:var(--action);font-size:var(--fs-small);font-weight:var(--fw-semi)}
.spinner{width:16px;height:16px;flex:none;border-radius:var(--r-pill);
  border:2px solid var(--border);border-top-color:var(--action);animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.pair-qr{width:180px;height:180px;margin:0 auto}
.pair-qr img{width:100%;height:100%;display:block}
.pair-addr{margin:0;font-size:var(--fs-label);color:var(--ink-muted);word-break:break-all}
[hidden]{display:none!important}
</style>
</head>
<body>
<div class="gallery">
  <div class="machine-window">
    <div class="machine-window__bar"><span class="machine-window__dot" id="dot"></span><span class="machine-window__t">ArrowBridge companion</span></div>
    <div class="machine-window__body">

      <div id="state-idle">
        <div class="idle-row"><span class="idle-dot"></span> Running - waiting for a device to pair</div>
        $qr_block
        <p class="pair-addr">$device_name &middot; $address_display</p>
        <button class="btn" id="start-btn" type="button">Start pairing</button>
      </div>

      <div id="state-code" hidden>
        <h2>A phone wants to pair with this computer</h2>
        <p class="p-muted">If this is you, check that your phone shows the same four digits, then confirm here.</p>
        <div class="matchcode"><p class="matchcode__code" id="code-digits"></p></div>
        <div class="keypress-hint">Press <kbd>Y</kbd> to confirm it's you, or <kbd>N</kbd> if it isn't</div>
        <div class="matchcode__acts">
          <button class="btn" id="yes-btn" type="button">Yes, that's my phone</button>
          <button class="btn btn--ghost" id="no-btn" type="button">Not me</button>
        </div>
        <div class="truth">
          <p class="truth__h">Why this asks twice</p>
          <p class="truth__p">Your phone shows the same four digits. Confirming on both the phone and this computer is what stops someone else on the same network pairing while you're not sitting here.</p>
        </div>
      </div>

      <div id="state-confirmed" hidden>
        <div class="matchcode"><p class="matchcode__code" style="opacity:.5" id="code-digits-dim"></p></div>
        <div class="pending-row"><span class="spinner"></span> Waiting for the phone to confirm too</div>
        <p class="p-muted">Pairing finishes once both sides agree - not before.</p>
      </div>

      <div id="state-failed" hidden>
        <h2>Nothing paired</h2>
        <p class="p-muted">Either nobody confirmed in time, or one side said no. Ask the phone to try again if this was you.</p>
        <div class="idle-row" style="justify-content:center"><span class="idle-dot" style="background:var(--ink-muted)"></span> Back to waiting</div>
      </div>

    </div>
  </div>
</div>
<script>
(function(){
  var elIdle = document.getElementById('state-idle');
  var elCode = document.getElementById('state-code');
  var elConfirmed = document.getElementById('state-confirmed');
  var elFailed = document.getElementById('state-failed');
  var startBtn = document.getElementById('start-btn');
  var yesBtn = document.getElementById('yes-btn');
  var noBtn = document.getElementById('no-btn');
  var codeDigits = document.getElementById('code-digits');
  var codeDigitsDim = document.getElementById('code-digits-dim');
  var handshakeId = null;
  var sawCode = false;
  var sawSuccess = false;
  var pollTimer = null;

  function show(el){
    [elIdle, elCode, elConfirmed, elFailed].forEach(function(e){ e.hidden = (e !== el); });
  }
  function formatCode(code){
    return String(code).split('').join(' ');
  }
  function stopPolling(){
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }
  function backToIdle(){
    stopPolling();
    handshakeId = null; sawCode = false; sawSuccess = false;
    startBtn.hidden = false;
    show(elIdle);
  }

  function poll(){
    fetch('/pair-status').then(function(res){
      if (!res.ok) {
        stopPolling();
        if (sawSuccess) { backToIdle(); } else { show(elFailed); setTimeout(backToIdle, 3000); }
        return null;
      }
      return res.json();
    }).then(function(data){
      if (!data) return;
      handshakeId = data.handshake_id || handshakeId;
      if (data.phone_confirmed) { sawSuccess = true; }
      if (data.code) {
        sawCode = true;
        if (data.machine_confirmed) {
          codeDigitsDim.textContent = formatCode(data.code);
          show(elConfirmed);
        } else {
          codeDigits.textContent = formatCode(data.code);
          show(elCode);
        }
      }
    }).catch(function(){ /* a single missed poll is not a failure - the next tick retries */ });
  }

  startBtn.addEventListener('click', function(){
    fetch('/pair-open', {method: 'POST'}).then(function(){
      startBtn.hidden = true;
      pollTimer = setInterval(poll, 1000);
      poll();
    });
  });
  yesBtn.addEventListener('click', function(){
    if (!handshakeId) return;
    fetch('/pair-confirm', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({handshake_id: handshakeId}),
    });
  });
  noBtn.addEventListener('click', function(){
    stopPolling();
    fetch('/pair-cancel', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({handshake_id: handshakeId}),
    }).then(function(){ show(elFailed); setTimeout(backToIdle, 3000); });
  });
  document.addEventListener('keydown', function(ev){
    if (elCode.hidden) return;
    var k = (ev.key || '').toLowerCase();
    if (k === 'y') yesBtn.click();
    if (k === 'n') noBtn.click();
  });
})();
</script>
</body>
</html>""")


def _pair_page_html():
    """Builds the GET /pair page. Reads the device name fresh on every request, so a page left
    open still reflects an operator who edits ARROWBRIDGE_DEVICE_NAME."""
    from discovery import _default_device_name
    name = _default_device_name()
    address = _pairing_address()
    if address:
        payload = _pairing_qr_payload(address, name)
        try:
            qr_src = _pairing_qr_svg_data_uri(payload)
            qr_block = ('<div class="pair-qr"><img alt="Scan with your ArrowBridge client to pair" '
                        'src="%s"></div>' % qr_src)
        except Exception:  # noqa: BLE001 - a missing/broken segno degrades to no QR, not a 500
            qr_block = '<p class="p-muted">Could not generate a QR code (segno unavailable).</p>'
        address_display = address
    else:
        qr_block = ('<p class="p-muted">Bind a LAN address (ARROWBRIDGE_BIND) to show a '
                    'scannable code here.</p>')
        address_display = "(loopback only, not reachable from a phone)"
    return _PAIR_PAGE_HTML_TEMPLATE.substitute(
        qr_block=qr_block,
        device_name=html.escape(name),
        address_display=html.escape(address_display),
    )


# ------------------------------------------------------------ /pair-test page
# Plain HTML/JS, no framework, no build step. The key is typed by the person testing, read from a
# `?key=` URL param if present, and used ONLY in this page's own fetch() calls to this same
# origin's /chat. A key in a URL lands in that browser's history; the README says so.
_PAIR_TEST_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ArrowBridge test</title>
<style>
body{font:16px system-ui,sans-serif;max-width:32rem;margin:2rem auto;padding:0 1rem}
textarea,input{width:100%;box-sizing:border-box;font:inherit;padding:.5rem}
button{font:inherit;padding:.5rem 1rem;margin-top:.5rem}
#reply{white-space:pre-wrap;border:1px solid #888;border-radius:.5rem;padding:.75rem;margin-top:1rem;min-height:3rem}
#status{color:#888;font-size:.9rem}
</style></head>
<body>
<h1>ArrowBridge test</h1>
<p>Pairing key (from the machine that started the companion):</p>
<input id="key" type="text">
<p>Message:</p>
<textarea id="msg" rows="3">hello</textarea>
<button id="send">Send</button>
<p id="status"></p>
<div id="reply"></div>
<script>
const params = new URLSearchParams(location.search);
const keyField = document.getElementById('key');
if (params.get('key')) keyField.value = params.get('key');
document.getElementById('send').onclick = async () => {
  const statusEl = document.getElementById('status');
  const replyEl = document.getElementById('reply');
  statusEl.textContent = 'sending...';
  replyEl.textContent = '';
  try {
    const res = await fetch('/chat', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-ArrowBridge-Pair': keyField.value,
      },
      body: JSON.stringify({message: document.getElementById('msg').value}),
    });
    const data = await res.json();
    statusEl.textContent = 'HTTP ' + res.status;
    replyEl.textContent = data.reply || JSON.stringify(data);
  } catch (e) {
    statusEl.textContent = 'request failed';
    replyEl.textContent = String(e);
  }
};
</script>
</body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _send_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # A slow or stalled client holds one thread, not the server, and not forever.
    timeout = 60

    def _read_json(self):
        """The request body (already read by do_POST) as JSON, {} when there is none. Raises
        ValueError on malformed JSON."""
        return json.loads(self._body.decode("utf-8")) if self._body else {}

    def _pair_gate(self):
        """Refuse an unpaired caller. Returns True when the request was REFUSED and handled.

        Called first in both do_GET and do_POST, before any routing, so a route added later is
        gated by default rather than by the author remembering. 404, not 401: a scanner on a
        shared network learns nothing about what is here."""
        if _pairing_ok(self.headers):
            return False
        logger.info("%s - refused, not paired", self.address_string())
        self._send_json(404, {"error": "not found"})
        return True

    def _pair_session_gate(self):
        """Refuse anything but the real raw key. Returns True when refused. See `_raw_key_ok`."""
        if _raw_key_ok(self.headers):
            return False
        logger.info("%s - /pair-session refused, no raw key presented", self.address_string())
        self._send_json(404, {"error": "not found"})
        return True

    def _pair_info_gate(self):
        """Refuse anything that is not a genuinely local caller. Returns True when refused."""
        if _pair_info_ok(self.client_address[0], self.headers):
            return False
        logger.info("%s - /pair-info refused, not a genuine local caller", self.address_string())
        self._send_json(404, {"error": "not found"})
        return True

    def _handle_pair_info(self):
        """Returns PAIR_KEY in plaintext, to a genuinely local caller only. Any local process on
        this machine can read it: correct for a single-owner machine, wrong the moment this is a
        shared one. Do not call this from anything that logs or transcribes its output; open it
        in a browser on the machine and carry the value to the phone yourself."""
        scheme = "https" if TLS_ENABLED else "http"
        addresses = ["%s://127.0.0.1:%d" % (scheme, PORT)]
        if LAN_EXPOSED:
            addresses.append("%s://%s:%d" % (scheme, BIND_HOST, PORT))
        self._send_json(200, {"pair_key": PAIR_KEY, "addresses": addresses, "tls": TLS_ENABLED})

    # -------------------------------------------------------- pairing handshake
    def _local_owner_gate(self):
        """Refuse anything that is not the owner's own machine. Returns True when refused."""
        if _local_owner_ok(self.client_address[0], self.headers):
            return False
        logger.info("%s - pairing-owner route refused, not a genuine local caller",
                     self.address_string())
        self._send_json(404, {"error": "not found"})
        return True

    def _pairing_window_gate(self):
        """Refuse a pairing-protocol route when no window is open. Returns True when refused."""
        if _pairing_window_is_open():
            return False
        logger.info("%s - pairing route refused, no window open", self.address_string())
        self._send_json(404, {"error": "not found"})
        return True

    def _handle_pair_open(self):
        """POST /pair-open, loopback only: the owner opens the window. A loopback HTTP route
        rather than a terminal keypress because a background run has no terminal; a local page
        or a one-line curl at the machine both satisfy it. Idempotent: opening an already-open
        window extends it and drops whatever partial handshake existed."""
        _open_pairing_window()
        self._send_json(200, {"open": True, "expires_in": PAIRING_WINDOW_SECONDS})

    def _handle_pair_status(self):
        """GET /pair-status, loopback only: the local page's polling route for the four-digit
        code. Never reachable by the phone. `code` stays None until the phone's reveal has been
        received and verified; the code cannot exist before both nonces are known."""
        with _pairing_lock:
            hs = dict(_active_handshake) if _active_handshake else None
        if hs is None:
            self._send_json(200, {"open": True, "handshake_id": None, "code": None,
                                   "revealed": False, "machine_confirmed": False,
                                   "phone_confirmed": False})
            return
        self._send_json(200, {
            "open": True,
            "handshake_id": hs["id"],
            "code": hs.get("code"),
            "revealed": hs.get("revealed", False),
            "machine_confirmed": hs["machine_confirmed"],
            "phone_confirmed": hs["finished"],
        })

    def _handle_pair_start(self):
        """POST /pair-start, no credential required, gated only on the window being open. Round
        one of mutual commit-then-reveal: the phone's public key and commitment in, the
        companion's public key and commitment out. Neither nonce, and therefore no code, exists
        as an observable quantity yet."""
        global _active_handshake
        try:
            body = self._read_json()
            phone_pub_b64 = body["public_key"]
            phone_pub = base64.b64decode(phone_pub_b64, validate=True)
            phone_commitment = base64.b64decode(body["commitment"], validate=True)
        except (ValueError, KeyError, binascii.Error):
            self._send_json(400, {"error": 'expected a JSON body with base64 "public_key" and '
                                            '"commitment"'})
            return
        if len(phone_commitment) != 32:
            self._send_json(400, {"error": "commitment must be a 32-byte SHA-256 digest"})
            return
        from cryptography.exceptions import InvalidKey
        from cryptography.hazmat.primitives.asymmetric import x25519
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        try:
            phone_public_key = x25519.X25519PublicKey.from_public_bytes(phone_pub)
        except (ValueError, InvalidKey):
            self._send_json(400, {"error": "invalid X25519 public key"})
            return
        with _pairing_lock:
            if _active_handshake is not None and not _active_handshake["finished"] \
                    and not _active_handshake.get("failed"):
                self._send_json(409, {"error": "a handshake is already in progress"})
                return
            companion_private_key = x25519.X25519PrivateKey.generate()
            companion_pub = companion_private_key.public_key().public_bytes(
                encoding=Encoding.Raw, format=PublicFormat.Raw)
            # The companion's nonce is picked now, having seen only the phone's commitment (a
            # preimage-resistant hash), never its nonce. Its commitment goes out; the nonce stays.
            companion_nonce = secrets.token_bytes(16)
            companion_commitment = _commitment(companion_nonce, companion_pub)
            shared_secret = companion_private_key.exchange(phone_public_key)
            handshake_id = secrets.token_urlsafe(16)
            _active_handshake = {
                "id": handshake_id,
                "phone_pub": phone_pub,
                "phone_commitment": phone_commitment,
                "companion_pub": companion_pub,
                "companion_nonce": companion_nonce,
                "companion_commitment": companion_commitment,
                "shared_secret": shared_secret,
                "phone_nonce": None,
                "session_key": None,
                "code": None,
                "revealed": False,
                "machine_confirmed": False,
                "finished": False,
                "failed": False,
            }
        logger.info("pairing handshake %s started (commitments exchanged, no nonce revealed)",
                     handshake_id)
        self._send_json(200, {
            "handshake_id": handshake_id,
            "public_key": base64.b64encode(companion_pub).decode("ascii"),
            "commitment": base64.b64encode(companion_commitment).decode("ascii"),
        })

    def _handle_pair_reveal(self):
        """POST /pair-reveal, round two. The phone reveals its nonce; this verifies it against the
        round-one commitment (constant-time compare). Only on a match does the companion reveal
        its own nonce, and only then does the four-digit code start existing anywhere.

        THE PHONE MUST PERFORM THE EQUIVALENT CHECK on what this response reveals:
        H(companion_nonce || companion_pubkey) == the companion_commitment from round one. This
        server can only prove it is not lying about its own side. A client that skips this check
        is open to the grinding attack on the other leg."""
        global _active_handshake
        try:
            body = self._read_json()
            handshake_id = body["handshake_id"]
            phone_nonce = base64.b64decode(body["nonce"], validate=True)
        except (ValueError, KeyError, binascii.Error):
            self._send_json(400, {"error": 'expected a JSON body with "handshake_id" and a '
                                            'base64 "nonce"'})
            return
        with _pairing_lock:
            hs = _active_handshake
            if hs is None or hs["id"] != handshake_id or hs["finished"] or hs.get("failed") \
                    or hs.get("revealed"):
                self._send_json(404, {"error": "not found"})
                return
            expected_commitment = _commitment(phone_nonce, hs["phone_pub"])
            if not hmac.compare_digest(expected_commitment, hs["phone_commitment"]):
                hs["failed"] = True
                logger.info("pairing handshake %s reveal refused: phone nonce did not match "
                             "its earlier commitment", handshake_id)
                _close_pairing_window_locked()
                self._send_json(404, {"error": "not found"})
                return
            session_key, code = _derive_pairing_material(
                hs["shared_secret"], phone_nonce, hs["companion_nonce"],
                hs["companion_pub"], hs["phone_pub"])
            hs["phone_nonce"] = phone_nonce
            hs["session_key"] = session_key
            hs["code"] = code
            hs["revealed"] = True
            companion_nonce = hs["companion_nonce"]
        logger.info("pairing handshake %s revealed (both commitments verified)", handshake_id)
        self._send_json(200, {"companion_nonce": base64.b64encode(companion_nonce).decode("ascii")})

    def _handle_pair_confirm(self):
        """POST /pair-confirm, loopback only: the owner, having read the four digits and seen
        them match the phone's display. Marks the handshake confirmed; issues nothing itself.
        Requires the reveal round to have happened, there is no code to have confirmed otherwise."""
        global _active_handshake
        try:
            body = self._read_json()
            handshake_id = body["handshake_id"]
        except (ValueError, KeyError):
            self._send_json(400, {"error": 'expected a JSON body with "handshake_id"'})
            return
        with _pairing_lock:
            hs = _active_handshake
            if hs is None or hs["id"] != handshake_id or hs["finished"] or hs.get("failed") \
                    or not hs.get("revealed"):
                self._send_json(404, {"error": "not found"})
                return
            hs["machine_confirmed"] = True
        logger.info("pairing handshake %s confirmed at the machine", handshake_id)
        self._send_json(200, {"machine_confirmed": True})

    def _handle_pair_cancel(self):
        """POST /pair-cancel, loopback only: the owner's "No" at the machine (the pairing page's
        "Not me" button). Closes the window immediately instead of waiting out the timer."""
        _close_pairing_window()
        logger.info("pairing window cancelled at the machine")
        self._send_json(200, {"cancelled": True})

    def _handle_pair_finish(self):
        """POST /pair-finish, no credential required, gated only on the window being open. Issues
        the phone's credential, encrypted under the session key, ONLY when the reveal round
        succeeded, the machine confirmed, AND the phone's HMAC proof over the handshake id
        verifies under the session key both sides derived independently. Any other outcome issues
        nothing and closes the window."""
        global _active_handshake
        try:
            body = self._read_json()
            handshake_id = body["handshake_id"]
            proof_hex = body["proof"]
        except (ValueError, KeyError):
            self._send_json(400, {"error": 'expected a JSON body with "handshake_id" and "proof"'})
            return
        with _pairing_lock:
            hs = _active_handshake
            if hs is None or hs["id"] != handshake_id or hs["finished"] or hs.get("failed") \
                    or not hs.get("revealed"):
                _close_pairing_window_locked()
                self._send_json(404, {"error": "not found"})
                return
            expected_proof = hmac.new(hs["session_key"], handshake_id.encode("utf-8"),
                                       "sha256").hexdigest()
            try:
                proof_matches = hmac.compare_digest(proof_hex, expected_proof)
            except TypeError:
                proof_matches = False
            if not hs["machine_confirmed"] or not proof_matches:
                hs["failed"] = True
                logger.info("pairing handshake %s finish refused (machine_confirmed=%s, "
                             "proof_ok=%s)", handshake_id, hs["machine_confirmed"], proof_matches)
                _close_pairing_window_locked()
                self._send_json(404, {"error": "not found"})
                return
            hs["finished"] = True
            session_key = hs["session_key"]

        credential = _mint_phone_credential(handshake_id)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(session_key)
        aad = handshake_id.encode("utf-8")
        cred_nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(cred_nonce, credential.encode("utf-8"), aad)
        logger.info("pairing handshake %s finished, credential issued", handshake_id)
        _close_pairing_window()
        self._send_json(200, {
            "credential_nonce": base64.b64encode(cred_nonce).decode("ascii"),
            "credential_ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        })

    def do_GET(self):
        # The one exception to "_pair_gate first": /pair-test is a static page with no secret in
        # it (the key is typed into it by a human), so serving the shell to an unpaired scanner
        # leaks nothing, and a plain browser navigation cannot set a custom header, so this page
        # is the one way a phone's browser can exercise /chat without a native app. Every fetch()
        # the page makes still goes through the real gate.
        if self.path == "/pair-test":
            self._send_pair_test_page()
            return
        if self.path == "/pair-info":
            if self._pair_info_gate():
                return
            self._handle_pair_info()
            return
        if self.path == "/pair-status":
            if self._local_owner_gate():
                return
            if self._pairing_window_gate():
                return
            self._handle_pair_status()
            return
        if self.path == "/pair":
            if self._local_owner_gate():
                return
            self._send_pair_page()
            return
        if self._pair_gate():
            return
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "upstream": UPSTREAM_URL,
                                   "model": UPSTREAM_MODEL or None,
                                   "models": sorted(MODEL_MAP), "pack_active": PACK_ACTIVE})
            return
        self._send_json(404, {"error": "not found"})

    def _send_pair_test_page(self):
        """A minimal, dependency-free chat tester so a phone browser can prove the whole path
        end to end without a native app. A text box and a send button, on purpose."""
        body = _PAIR_TEST_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_pair_page(self):
        """GET /pair, loopback only: the machine-side pairing page. Never the phone's route; the
        phone finds this machine's address by scanning the QR this page shows."""
        body = _pair_page_html().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_pair_session(self):
        """POST /pair-session: exchanges the raw key for a fresh short-lived session token. The
        caller has already passed the raw-key-only gate, so minting is unconditional here."""
        self._send_json(200, {"token": _mint_session_token(),
                               "expires_in": SESSION_TOKEN_TTL_SECONDS})

    def _send_chat_json(self, code, payload):
        """The one place every /chat response passes through. A payload with no "reply" key gets
        the safety module's footer put there, if one is present, so a caller that only knows to
        display `reply` sees it whether the turn succeeded or not. Composed here so a branch
        added later cannot forget it."""
        if "reply" not in payload:
            tail = floor_text()
            if tail:
                payload = dict(payload, reply=tail)
        self._send_json(code, payload)

    def do_POST(self):
        # Read the whole body FIRST, before any gate can answer. A response written while the
        # request body still sits unread makes the socket close with a reset, and a Windows
        # client then drops the response it had not read yet: a refused POST would look like a
        # dead server. Bounded, because this runs before authentication.
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "malformed Content-Length"})
            return
        if not 0 <= length <= MAX_BODY_BYTES:
            self._send_json(400, {"error": "invalid or oversized Content-Length"})
            return
        self._body = self.rfile.read(length) if length else b""
        # urlsplit, not a bare == on self.path: a client may request "/v1/messages?beta=true".
        path = urllib.parse.urlsplit(self.path).path
        # Routes checked BEFORE the general gate, each on its own stricter or different check:
        # /pair-session on the raw key only (see _raw_key_ok); /pair-open, /pair-confirm and
        # /pair-cancel on the owner's own machine (loopback, no proxy header); /pair-start,
        # /pair-reveal and /pair-finish unauthenticated on purpose (the phone has no credential
        # yet) and safe only because they are also gated on the window the owner opened.
        if path == "/pair-session":
            if self._pair_session_gate():
                return
            self._handle_pair_session()
            return
        if path == "/pair-open":
            if self._local_owner_gate():
                return
            self._handle_pair_open()
            return
        if path == "/pair-confirm":
            if self._local_owner_gate():
                return
            if self._pairing_window_gate():
                return
            self._handle_pair_confirm()
            return
        if path == "/pair-cancel":
            if self._local_owner_gate():
                return
            self._handle_pair_cancel()
            return
        if path == "/pair-start":
            if self._pairing_window_gate():
                return
            self._handle_pair_start()
            return
        if path == "/pair-reveal":
            if self._pairing_window_gate():
                return
            self._handle_pair_reveal()
            return
        if path == "/pair-finish":
            if self._pairing_window_gate():
                return
            self._handle_pair_finish()
            return
        if self._pair_gate():
            return
        if path == "/v1/messages/count_tokens":
            self._handle_count_tokens()
            return
        if path == "/v1/messages":
            self._handle_messages()
            return
        if path != "/chat":
            self._send_chat_json(404, {"error": "not found"})
            return
        try:
            body = self._read_json()
            message = body["message"]
        except (ValueError, KeyError):
            self._send_chat_json(400, {"error": 'expected a JSON body with a "message" string'})
            return
        try:
            model_text = call_upstream(message, body.get("history"))
        except NotConfigured as exc:
            self._send_chat_json(500, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - one bad upstream call must not stop the server
            logger.error("upstream call failed (%s)", type(exc).__name__)
            self._send_chat_json(502, {"error": "could not reach the local model"})
            return
        reply = compose_reply(model_text)
        self._send_chat_json(200, {"reply": reply, "model": UPSTREAM_MODEL, "backend": "local"})

    def _send_messages_json(self, text, stop_reason=_STOP_REASON_DEFAULT, usage=None, stream=False,
                             model=None):
        """The one place every /v1/messages response passes through. `text` is already composed:
        a real model turn arrives via `compose_reply`, every error branch via `_with_floor`.

        ponytail: always answers 200, on a malformed body and an unreachable upstream alike. A
        Messages-API client renders body text as a chat message only on a 2xx; on anything else
        it shows a generic error banner and the explanation (and any footer) is never seen."""
        if stream:
            body = _build_sse_body(text, stop_reason, usage, model=model).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self._send_json(200, _anthropic_message_payload(text, stop_reason, usage, model=model))

    def _handle_messages(self):
        """POST /v1/messages. The request's `model` field is resolved against MODEL_MAP, the only
        thing the request may influence about which upstream answers; an unknown name falls back
        to the default and logs it, never fails the request."""
        stream_requested = False
        try:
            body = self._read_json()
            stream_requested = bool(body.get("stream"))
        except ValueError:
            self._send_messages_json(_with_floor("(malformed request body)"), stream=stream_requested)
            return
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            self._send_messages_json(
                _with_floor('(expected a non-empty "messages" array)'), stream=stream_requested)
            return
        model_id, url = resolve_model(body.get("model"))
        logger.info("routing request (requested=%r) to model=%r", body.get("model"), model_id)
        note_model_switch(model_id)
        try:
            result = call_upstream_messages(messages, body.get("max_tokens"),
                                             model_id=model_id, url=url)
        except NotConfigured as exc:
            self._send_messages_json(_with_floor(str(exc)), stream=stream_requested, model=model_id)
            return
        except Exception as exc:  # noqa: BLE001 - one bad upstream call must not stop the server
            logger.error("upstream /v1/messages call failed for model %r (%s)",
                         model_id, type(exc).__name__)
            self._send_messages_json(
                _with_floor("(could not reach the local model)"),
                stream=stream_requested, model=model_id)
            return
        reply = compose_reply(result["text"])
        self._send_messages_json(reply, stop_reason=result["stop_reason"], usage=result["usage"],
                                  stream=stream_requested, model=result.get("model", model_id))

    def _handle_count_tokens(self):
        """POST /v1/messages/count_tokens: a pass-through to the upstream's endpoint of the same
        name, model field overwritten like every other route. No footer: this returns a token
        count, never narrative content. It exists because some Messages-API clients hang against
        an upstream that has every other endpoint but not this one."""
        try:
            body = self._read_json()
        except ValueError:
            self._send_json(400, {"error": "malformed request body"})
            return
        if not UPSTREAM_MODEL:
            self._send_json(500, {"error": "ARROWBRIDGE_UPSTREAM_MODEL is not set"})
            return
        body = dict(body, model=UPSTREAM_MODEL)
        headers = {"Content-Type": "application/json"}
        if UPSTREAM_KEY:
            headers["Authorization"] = "Bearer " + UPSTREAM_KEY
        req = urllib.request.Request(
            UPSTREAM_URL + "/v1/messages/count_tokens",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
        except Exception as exc:  # noqa: BLE001 - one bad upstream call must not stop the server
            logger.error("count_tokens upstream call failed (%s)", type(exc).__name__)
            self._send_json(502, {"error": "could not reach the local model"})
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        # Method, path, status. Never the request body, never a reply.
        logger.info("%s - %s", self.address_string(), fmt % args)


if __name__ == "__main__":
    # A key always exists by the time execution reaches here. Print a generated one once, so an
    # operator who never set ARROWBRIDGE_PAIR_KEY can still pair a device rather than discovering
    # a 404 with no way to learn why.
    if PAIR_KEY_WAS_GENERATED:
        logger.info(
            "No ARROWBRIDGE_PAIR_KEY was set - generated one for this run only (a restart makes "
            "a new one): %s . Callers send it as `X-ArrowBridge-Pair: <key>` (or a bearer "
            "token). Set ARROWBRIDGE_PAIR_KEY yourself for a key that survives a restart.",
            PAIR_KEY)

    # One TLS variable set and not the other is a config mistake, not a partial feature.
    if bool(TLS_CERT) != bool(TLS_KEY):
        sys.stderr.write(
            "ArrowBridge REFUSES TO START.\n"
            "  Only one of ARROWBRIDGE_TLS_CERT/ARROWBRIDGE_TLS_KEY is set. Set both (a PEM\n"
            "  certificate and its key) or neither - pairing-key-only mode already works.\n")
        raise SystemExit(2)
    server_cls = socketserver.ThreadingTCPServer
    if TLS_ENABLED:
        try:
            server_cls = _TLSThreadingTCPServer
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(TLS_CERT, TLS_KEY)
        except (ssl.SSLError, OSError) as exc:
            sys.stderr.write(
                "ArrowBridge REFUSES TO START.\n"
                "  ARROWBRIDGE_TLS_CERT/_KEY are set but did not load (%s: %s).\n"
                "  BREAK-GLASS: unset both variables and restart - that drops straight back to\n"
                "  pairing-key-only mode, never a lockout.\n"
                % (type(exc).__name__, exc))
            raise SystemExit(2)

    logger.info("ArrowBridge companion listening on %s:%d, upstream %s, models=%s, tls=%s",
                 BIND_HOST, PORT, UPSTREAM_URL,
                 sorted(MODEL_MAP) or "(ARROWBRIDGE_MODEL_MAP empty)", TLS_ENABLED)
    # mDNS discovery, so a phone finds this machine by name on the same physical network.
    # ARROWBRIDGE_NO_DISCOVERY=1 skips it; a machine with no `zeroconf` installed degrades to
    # "type the address in by hand", never a hard failure.
    advertiser = None
    if LAN_EXPOSED and os.environ.get("ARROWBRIDGE_NO_DISCOVERY", "").strip() != "1":
        try:
            from discovery import Advertiser
            advertiser = Advertiser()
            advertiser.start(port=PORT, pair_required=True)
        except Exception as exc:  # noqa: BLE001 - discovery is a convenience, never load-bearing
            logger.warning(
                "mDNS discovery unavailable (%s: %s) - the companion still works, a phone just "
                "needs the address typed in by hand instead of finding it automatically.",
                type(exc).__name__, exc)
    if LAN_EXPOSED:
        logger.info("LAN reachable: every request must carry the pairing key. This path needs "
                     "no internet - a phone on this network reaches the model with no upstream "
                     "connectivity at all.")
    if TLS_ENABLED:
        logger.info("TLS on: cert=%s. BREAK-GLASS if this cert ever fails a caller (expired, "
                     "device offline too long to renew): unset ARROWBRIDGE_TLS_CERT/_KEY and "
                     "restart - pairing-key-only mode is unaffected.", TLS_CERT)
    try:
        server_cls((BIND_HOST, PORT), Handler).serve_forever()
    finally:
        # A stale mDNS entry advertising a companion that already exited would answer the phone
        # with a dead address - stop announcing the instant this process stops serving.
        if advertiser is not None:
            advertiser.stop()
