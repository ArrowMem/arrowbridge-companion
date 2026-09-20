# ArrowBridge companion

A small local HTTP checkpoint that sits between a model running on your own machine and the
phone or client asking it questions. It pairs by a pinned key on your own LAN, binds to one
specific interface and never `0.0.0.0`, and removes telephone numbers the model invented before
the reply reaches you. Proven with the internet physically disconnected: a phone on the same
network reached a model on the machine beside it, with no upstream connectivity anywhere in the
path.

## What it is not

- Not a model server. You bring one: llama.cpp's server on `127.0.0.1:8080` or Ollama on
  `127.0.0.1:11434`. This program talks to it over loopback and to nothing else.
- Not a VPN, a mesh, or a way to reach your machine from outside your network. One phone, one
  machine, one network.
- Not a general content filter. The one thing it strips is a telephone-shaped string, and it
  strips every one of them except 911 unless a safety module says otherwise (see below).
- Not a clinical, legal or emergency service, and not a client app. The phone side of the
  numeric-comparison pairing is a client's job; this repo ships the server and a test driver.
- Not encrypted on the wire unless you give it a certificate. See "What this does not protect
  against".

## Quickstart

Tested on Python 3.12. Nothing here needs the internet after `pip install`.

```
pip install -r requirements.txt
set ARROWBRIDGE_UPSTREAM_MODEL=<the model name your local server loads>
python companion_server.py
```

The startup log prints a pairing key for this run (or set `ARROWBRIDGE_PAIR_KEY` yourself for
one that survives a restart). From another window on the same machine:

```
curl.exe -s -X POST http://127.0.0.1:8788/chat -H "Content-Type: application/json" ^
    -H "X-ArrowBridge-Pair: <key from the startup log>" -d "{\"message\": \"hello\"}"
```

You get `{"reply": "...", "model": "...", "backend": "local"}`. If the reply is a 502, the
companion is up and your model server is not.

`ARROWBRIDGE_UPSTREAM_URL` defaults to `http://127.0.0.1:8080`; set it to
`http://127.0.0.1:11434` for Ollama, and set `ARROWBRIDGE_UPSTREAM_KEY=` (empty) if your server
wants no Authorization header. `ARROWBRIDGE_SYSTEM_PROMPT_FILE` points at a text file to run
your model under; it is the only source of a system prompt, a client cannot supply one.

### Reaching it from a phone on the same network

Find the address of the interface your phone shares with this machine (`ipconfig` on Windows,
`ip addr` or `ifconfig` elsewhere). Say it is `192.0.2.10`. Then:

```
set ARROWBRIDGE_BIND=192.0.2.10
set ARROWBRIDGE_PAIR_KEY=<a long random string>
set ARROWBRIDGE_UPSTREAM_MODEL=<as above>
python companion_server.py
```

On the phone, open `http://192.0.2.10:8788/pair-test` in a browser, paste the key, and send a
message. That page is a text box and a button, on purpose: it proves the whole path without a
native app. With `zeroconf` installed the companion also advertises itself over mDNS as
`_arrowbridge._tcp.local.` so a client can find it by name; `ARROWBRIDGE_NO_DISCOVERY=1` turns
that off.

`start-companion.sh` does the same with the key read from a `0600` file instead of the
environment.

## The bind rule

`ARROWBRIDGE_BIND` takes the ONE address of the interface your phone actually uses. The program
refuses to start on `0.0.0.0` or `::` (exit code 2, and `test_wildcard_bind_is_refused_at_startup`
proves it). The wildcard would also listen on every other interface this machine has, present
and future, for zero benefit over naming the one you mean. The default, with the variable
unset, is `127.0.0.1`: only this machine can reach it.

Binding a LAN address is the change that deletes the loopback trust boundary. Anything on the
network can now connect, so a pairing key is required on every request, on every bind, loopback
included. There is no "no key needed" state; if you set none, one is generated per run and
printed once.

## The pairing model

Two devices, one owner, a pinned shared secret. No certificate authority: certificates expire
on a wall clock, and a machine that has been offline long enough for its clock to drift would
refuse its own certificate and lock its owner out. A shared secret has no expiry to get wrong.

Three credential kinds are accepted in the same header (`X-ArrowBridge-Pair: <value>`, or
`Authorization: Bearer <value>`), compared in constant time:

1. The pairing key itself, `ARROWBRIDGE_PAIR_KEY`.
2. A session token from `POST /pair-session`, minted only against the raw key (never against
   another token, so a captured token really does expire), 60 minutes, in memory.
3. A per-phone credential from the numeric-comparison handshake below, revocable on its own
   without rotating the key every other phone holds. In memory; a restart means re-pairing.

An unpaired caller gets `404` on every route, never `401`: a scanner on the network learns
nothing about what is here.

### Numeric comparison, for a client that implements it

The owner opens a 180 second window at the machine (`POST /pair-open`, loopback only, or the
button on `GET /pair`, the machine-side page). Phone and companion then run an X25519 key
agreement in two rounds, mutual commit-then-reveal:

- `POST /pair-start`: the phone sends its public key and `SHA256(phone_nonce || phone_pubkey)`,
  never the nonce. The companion answers with its public key and its own commitment, also never
  its nonce.
- `POST /pair-reveal`: the phone reveals its nonce. The companion checks it against the
  commitment, and only on a match reveals its own. The phone must perform the same check on
  what comes back; the server can only prove it is not lying about its own side.

Both sides derive the same four digits (HKDF over the shared secret, both public keys, both
nonces, phone's first). The owner reads them on the machine's screen and confirms there
(`POST /pair-confirm`, loopback only); the phone's human taps "yes, it matches", which sends
`POST /pair-finish` with an HMAC proof over the handshake id under the session key. Only with
both confirmations and a verified proof is a credential minted and returned, encrypted under
that session key. Outside the window every pairing route answers 404.

Why two rounds: a companion that revealed its nonce immediately would let an attacker in the
companion role grind key and nonce pairs offline until the four digits matched a target the
human would confirm. `_pairing_attacks.py` runs that attack against this protocol on every test
run. `test_pairing_handshake.py` is the complete phone side, in Python, for anyone writing a
client.

## Routes

| Route | Who | What |
| --- | --- | --- |
| `POST /chat` | paired | `{"message": "...", "history": [...]}` in, `{"reply": "..."}` out. Works with llama.cpp and Ollama. |
| `POST /v1/messages` | paired | The Messages API wire shape, proxied to an upstream that speaks it natively (llama.cpp's server does; Ollama does not). The caller's `system` is ignored; `model` is resolved against `ARROWBRIDGE_MODEL_MAP` (`NAME=upstream_model[@url]`, comma separated). Streaming requests get a valid SSE body carrying the whole reply in one delta, because the guard needs the complete text. |
| `POST /v1/messages/count_tokens` | paired | Pass-through. Some clients hang without it. |
| `GET /health` | paired | Upstream, model, configured model names. |
| `GET /pair-test` | anyone | The text-box test page. Contains no secret; the key is typed in. |
| `GET /pair-info` | this machine | Returns the pairing key. Any local process can read it. |
| `GET /pair` | this machine | Machine-side pairing page with a QR carrying the LAN address and a display name, never a key. |
| `POST /pair-open`, `/pair-confirm`, `/pair-cancel`, `GET /pair-status` | this machine | The owner's side of the handshake. |
| `POST /pair-start`, `/pair-reveal`, `/pair-finish` | anyone, window open | The phone's side of the handshake. |
| `POST /pair-session` | raw key only | Mint a session token. |

"This machine" means a loopback peer address with no proxy header (`X-Forwarded-For`,
`Forwarded`, or a VPN relay's identity header).

## The telephone guard

Every reply, on every route, passes through `tel_guard.py` before it leaves. Any string shaped
like a North American number, a five or six digit short code, or one of the two three-digit
lines the pattern names is removed, not masked; 911 is the one number kept. This is deliberate:
a model can be talked out of a prompt instruction, and it will invent a help line with complete
confidence. A five or six digit
quantity in a reply will be eaten too; that trade is accepted and documented in the file.

`companion_server.py` also looks for an optional module named `arrowbridge_pack`. If one is
importable it may append a footer to every reply and error body, run a second redaction pass,
and add telephone numbers the guard should let through. This repo ships no such module, so the
footer is empty and no second pass runs. The guard runs either way.

## What this does not protect against

- Plaintext on your LAN. Without `ARROWBRIDGE_TLS_CERT` and `ARROWBRIDGE_TLS_KEY` (a PEM
  certificate and key), anyone who can capture packets on your network segment can read the
  conversation. The pairing key stops them talking to the companion; it does not hide what you
  said. Use it on a network you control.
- The pairing key is the entire boundary once you bind a LAN address. Anyone who has it is you.
- `GET /pair-info` hands the key to any process on the machine. Fine for a single-owner
  machine, wrong for a shared one.
- A reverse proxy in front of the companion makes every caller look like loopback. The
  owner-only routes refuse requests carrying the common proxy headers, but a proxy that adds
  none cannot be detected. Do not put one in front of this.
- The phone must verify the companion's reveal itself (`SHA256(companion_nonce ||
  companion_pubkey)` against the round-one commitment). A client that skips that check is open
  to the grinding attack on the other leg. This repo has no phone client, only the test driver.
- `?key=` on `/pair-test` puts the key in that browser's history. Type it instead when you can.
- Your model server is your responsibility. This program does not bind it to loopback for you;
  check that it is not listening on the network itself. If you would rather have that check done
  for you, on this and everything else the machine exposes, ArrowMem Guard is the same team's
  machine sweep (arrowmem.ca/guard.html). It is separate from this program and optional.
- Everything the model says other than a telephone number reaches you unchanged.

## Tests

```
pip install pytest
python -m pytest -q
```

`test_discovery.py` puts a real mDNS service on the wire and browses for it; it needs a
LAN-reachable adapter and will also find any other ArrowBridge companion advertising on your
network.

## Where this sits

This is the LAN rung, on its own, and it is complete as it stands. ArrowMem is at arrowmem.ca.

## License

MIT, ArrowMem Inc. See `LICENSE`.

## Credits

Built by ArrowMem Inc. with Claude (Anthropic) as the coding collaborator. Reviewed adversarially by a second
model session that did not write it, and verified on a second machine that did not build it. Issues and pull
requests welcome.
