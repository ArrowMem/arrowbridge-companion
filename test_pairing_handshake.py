"""Tests for the numeric-comparison pairing handshake, mutual commit-then-reveal (see
companion_server.py's module docstring for the protocol and the attack it closes).

Drives the real HTTP layer (a real Handler on an ephemeral port), so these exercise the actual
routes and gates, not just the free functions behind them. `_derive` below is an independent
re-implementation of the server's key derivation, so a client author can read it as the phone
side of the protocol.

Run:  python -m pytest -q test_pairing_handshake.py
"""
import base64
import hashlib
import http.client
import json
import logging
import os
import secrets
import socketserver
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import companion_server as cs  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
import hmac as hmac_mod  # noqa: E402


def _start_server():
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), cs.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, httpd.server_address[1]


def _reset_pairing_state():
    """Every test starts from a clean slate, exactly like a restart would."""
    with cs._pairing_lock:
        cs._pairing_window["open"] = False
        cs._pairing_window["expires_at"] = None
        cs._active_handshake = None
    with cs._phone_credentials_lock:
        cs._phone_credentials.clear()


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _post(port, path, body, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    payload = json.dumps(body).encode("utf-8")
    hdrs = {"Content-Type": "application/json"}
    hdrs.update(headers or {})
    conn.request("POST", path, body=payload, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, raw, (json.loads(raw) if raw else {})


def _get(port, path, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers=headers or {})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, raw, (json.loads(raw) if raw else {})


def _phone_keypair():
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    return priv, pub


def _commitment(nonce, pubkey):
    return hashlib.sha256(nonce + pubkey).digest()


def _derive(shared_secret, phone_nonce, companion_nonce, companion_pub, phone_pub):
    """Independent re-implementation of companion_server._derive_pairing_material: proves the
    client-side math matches what the server does, not merely that the server calls its own
    function."""
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


def _run_happy_path(port):
    """Drives one complete two-round handshake. Returns (phone_response_bodies,
    phone_session_key, companion_code, phone_code, credential).

    `phone_response_bodies` holds the bodies of every JSON-shaped response in the flow except
    /pair-status, which is answered only to the owner's loopback poll, never to the phone."""
    phone_bodies = []

    status, _, body = _post(port, "/pair-open", {})
    assert status == 200
    phone_bodies.append(body)

    phone_priv, phone_pub = _phone_keypair()
    phone_nonce = secrets.token_bytes(16)
    phone_commitment = _commitment(phone_nonce, phone_pub)
    status, _, body = _post(port, "/pair-start",
                             {"public_key": _b64(phone_pub), "commitment": _b64(phone_commitment)})
    assert status == 200, body
    phone_bodies.append(body)
    handshake_id = body["handshake_id"]
    companion_pub = base64.b64decode(body["public_key"])
    companion_commitment = base64.b64decode(body["commitment"])

    status, _, reveal_body = _post(
        port, "/pair-reveal", {"handshake_id": handshake_id, "nonce": _b64(phone_nonce)})
    assert status == 200, reveal_body
    phone_bodies.append(reveal_body)
    companion_nonce = base64.b64decode(reveal_body["companion_nonce"])

    # The phone's own obligation: verify the companion's reveal against the commitment
    # /pair-start already gave it.
    assert _commitment(companion_nonce, companion_pub) == companion_commitment

    shared_secret = phone_priv.exchange(x25519.X25519PublicKey.from_public_bytes(companion_pub))
    phone_session_key, phone_code = _derive(
        shared_secret, phone_nonce, companion_nonce, companion_pub, phone_pub)

    status, _, status_body = _get(port, "/pair-status")
    assert status == 200
    companion_code = status_body["code"]

    status, _, confirm_body = _post(port, "/pair-confirm", {"handshake_id": handshake_id})
    assert status == 200
    phone_bodies.append(confirm_body)

    proof = hmac_mod.new(phone_session_key, handshake_id.encode("utf-8"), "sha256").hexdigest()
    status, _, finish_body = _post(port, "/pair-finish",
                                    {"handshake_id": handshake_id, "proof": proof})
    assert status == 200, finish_body
    phone_bodies.append(finish_body)

    cred_nonce = base64.b64decode(finish_body["credential_nonce"])
    ciphertext = base64.b64decode(finish_body["credential_ciphertext"])
    credential = AESGCM(phone_session_key).decrypt(
        cred_nonce, ciphertext, handshake_id.encode("utf-8")).decode("utf-8")

    return phone_bodies, phone_session_key, companion_code, phone_code, credential


def test_happy_path_both_sides_derive_identical_codes_and_credential_works():
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _, _, companion_code, phone_code, credential = _run_happy_path(port)
        assert companion_code == phone_code
        assert len(companion_code) == 4 and companion_code.isdigit()
        assert credential in cs._phone_credentials
        status, _, body = _get(port, "/health", headers={"X-ArrowBridge-Pair": credential})
        assert status == 200, body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_no_machine_confirm_never_issues_a_credential():
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _post(port, "/pair-open", {})
        phone_priv, phone_pub = _phone_keypair()
        phone_nonce = secrets.token_bytes(16)
        status, _, body = _post(port, "/pair-start", {
            "public_key": _b64(phone_pub), "commitment": _b64(_commitment(phone_nonce, phone_pub))})
        assert status == 200
        handshake_id = body["handshake_id"]
        companion_pub = base64.b64decode(body["public_key"])

        status, _, reveal_body = _post(
            port, "/pair-reveal", {"handshake_id": handshake_id, "nonce": _b64(phone_nonce)})
        assert status == 200
        companion_nonce = base64.b64decode(reveal_body["companion_nonce"])
        shared_secret = phone_priv.exchange(x25519.X25519PublicKey.from_public_bytes(companion_pub))
        phone_session_key, _code = _derive(
            shared_secret, phone_nonce, companion_nonce, companion_pub, phone_pub)

        # No /pair-confirm at all.
        proof = hmac_mod.new(phone_session_key, handshake_id.encode("utf-8"), "sha256").hexdigest()
        status, _, finish_body = _post(port, "/pair-finish",
                                        {"handshake_id": handshake_id, "proof": proof})
        assert status == 404, finish_body
        assert "credential_ciphertext" not in finish_body
        assert len(cs._phone_credentials) == 0
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_wrong_phone_proof_never_issues_a_credential():
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _post(port, "/pair-open", {})
        _priv, phone_pub = _phone_keypair()
        phone_nonce = secrets.token_bytes(16)
        status, _, body = _post(port, "/pair-start", {
            "public_key": _b64(phone_pub), "commitment": _b64(_commitment(phone_nonce, phone_pub))})
        assert status == 200
        handshake_id = body["handshake_id"]

        status, _, _ = _post(
            port, "/pair-reveal", {"handshake_id": handshake_id, "nonce": _b64(phone_nonce)})
        assert status == 200
        _post(port, "/pair-confirm", {"handshake_id": handshake_id})

        status, _, finish_body = _post(
            port, "/pair-finish", {"handshake_id": handshake_id, "proof": "0" * 64})
        assert status == 404, finish_body
        assert "credential_ciphertext" not in finish_body
        assert len(cs._phone_credentials) == 0
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_reveal_not_matching_commitment_is_refused():
    """A phone that lies at /pair-reveal (a nonce that does not hash to the commitment it sent
    at /pair-start) gets no credential and the handshake closes immediately."""
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _post(port, "/pair-open", {})
        _priv, phone_pub = _phone_keypair()
        real_nonce = secrets.token_bytes(16)
        status, _, body = _post(port, "/pair-start", {
            "public_key": _b64(phone_pub), "commitment": _b64(_commitment(real_nonce, phone_pub))})
        assert status == 200
        handshake_id = body["handshake_id"]

        wrong_nonce = secrets.token_bytes(16)
        assert wrong_nonce != real_nonce
        status, _, reveal_body = _post(
            port, "/pair-reveal", {"handshake_id": handshake_id, "nonce": _b64(wrong_nonce)})
        assert status == 404, reveal_body
        assert "companion_nonce" not in reveal_body

        # The handshake is dead: even the REAL nonce no longer works, and the window is closed.
        status, _, _ = _post(
            port, "/pair-reveal", {"handshake_id": handshake_id, "nonce": _b64(real_nonce)})
        assert status == 404
        assert len(cs._phone_credentials) == 0
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_pair_start_404s_after_the_window_closes():
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _post(port, "/pair-open", {})
        with cs._pairing_lock:
            cs._pairing_window["expires_at"] = time.monotonic() - 1  # force expiry
        _priv, phone_pub = _phone_keypair()
        nonce = secrets.token_bytes(16)
        status, _, body = _post(port, "/pair-start", {
            "public_key": _b64(phone_pub), "commitment": _b64(_commitment(nonce, phone_pub))})
        assert status == 404, body

        # Every pairing route answers 404 outside the window, not just /pair-start.
        status, _, _ = _post(port, "/pair-reveal", {"handshake_id": "x", "nonce": _b64(nonce)})
        assert status == 404
        status, _, _ = _post(port, "/pair-finish", {"handshake_id": "x", "proof": "y"})
        assert status == 404
        status, _, _ = _get(port, "/pair-status")
        assert status == 404
        status, _, _ = _post(port, "/pair-confirm", {"handshake_id": "x"})
        assert status == 404
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_two_concurrent_pair_starts_do_not_both_succeed():
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _post(port, "/pair-open", {})
        _priv1, pub1 = _phone_keypair()
        _priv2, pub2 = _phone_keypair()

        results = []

        def _attempt(pub):
            nonce = secrets.token_bytes(16)
            status, _, body = _post(port, "/pair-start", {
                "public_key": _b64(pub), "commitment": _b64(_commitment(nonce, pub))})
            results.append(status)

        t1 = threading.Thread(target=_attempt, args=(pub1,))
        t2 = threading.Thread(target=_attempt, args=(pub2,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results.count(200) == 1, results
        assert results.count(409) == 1, results
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_four_digit_code_never_appears_in_any_phone_response_body():
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        bodies, session_key, companion_code, phone_code, credential = _run_happy_path(port)
        assert companion_code == phone_code
        for body in bodies:
            serialized = json.dumps(body)
            assert companion_code not in serialized, (
                "the 4-digit code leaked into a phone-facing response body: %r" % body)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_companion_nonce_absent_until_after_reveal_is_verified():
    """Message-order proof: the companion's nonce is never present in /pair-start's response or
    anywhere before a verified /pair-reveal. Checks the literal wire bytes, not just a field
    name, so a nonce smuggled into an unexpected key would still be caught."""
    _reset_pairing_state()
    httpd, port = _start_server()
    try:
        _post(port, "/pair-open", {})
        _priv, phone_pub = _phone_keypair()
        phone_nonce = secrets.token_bytes(16)
        status, start_raw, start_body = _post(port, "/pair-start", {
            "public_key": _b64(phone_pub), "commitment": _b64(_commitment(phone_nonce, phone_pub))})
        assert status == 200
        assert set(start_body.keys()) == {"handshake_id", "public_key", "commitment"}, start_body

        status, _, status_body = _get(port, "/pair-status")
        assert status == 200
        assert status_body["code"] is None
        assert status_body["revealed"] is False

        handshake_id = start_body["handshake_id"]
        status, reveal_raw, reveal_body = _post(
            port, "/pair-reveal", {"handshake_id": handshake_id, "nonce": _b64(phone_nonce)})
        assert status == 200
        assert set(reveal_body.keys()) == {"companion_nonce"}, reveal_body
        companion_nonce_b64 = reveal_body["companion_nonce"]
        assert companion_nonce_b64 not in start_raw.decode("utf-8")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_no_key_or_secret_appears_in_logs():
    _reset_pairing_state()
    httpd, port = _start_server()
    log_capture = []

    class _Handler(logging.Handler):
        def emit(self, record):
            log_capture.append(self.format(record))

    handler = _Handler()
    cs.logger.addHandler(handler)
    try:
        _, session_key, _companion_code, _phone_code, credential = _run_happy_path(port)
    finally:
        cs.logger.removeHandler(handler)
        httpd.shutdown()
        httpd.server_close()

    log_text = "\n".join(log_capture)
    assert session_key.hex() not in log_text
    assert base64.b64encode(session_key).decode("ascii") not in log_text
    assert credential not in log_text


def test_grind_attack_cannot_force_a_matching_code():
    """Runs the grinding attack (_pairing_attacks.py) against the protocol at 5000 attempts.
    See that module's docstring for why zero correct commitment guesses, and therefore no forced
    match, is exactly what chance predicts at this count and not an artificially strict bound."""
    import _pairing_attacks

    result = _pairing_attacks.run_attack(attempts=5000)
    assert result["commitment_guesses_correct"] == 0, (
        "the attacker correctly guessed the phone's 128-bit nonce %d time(s) in %d attempts - "
        "astronomically unlikely by chance; investigate before assuming a fluke: %r" % (
            result["commitment_guesses_correct"], result["attempts"], result))
    assert result["forced_match"] is False, (
        "the grind attack forced a matching code against the protocol: %r" % result)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
