"""Tests for the machine-side pairing page, GET /pair.

Same real-HTTP-layer shape as test_companion_floor.py, and the same "assert shape and refusals,
never a secret value" discipline: this page never embeds the pairing digits (they only arrive
from /pair-status at runtime, after a window is opened), so there is no secret to print.
"""
import http.client
import os
import socketserver
import sys
import threading
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import companion_server as cs  # noqa: E402


def _H(extra=None):
    h = {}
    if extra:
        h.update(extra)
    return h


def _start_server():
    httpd = socketserver.ThreadingTCPServer(("127.0.0.1", 0), cs.Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, httpd.server_address[1]


# ---------------------------------------------------------------- owner-only gate
def test_local_owner_ok_shape_matches_what_pair_gates_on():
    assert cs._local_owner_ok("127.0.0.1", _H()) is True
    assert cs._local_owner_ok("::1", _H()) is True
    assert cs._local_owner_ok("192.0.2.50", _H()) is False, "a LAN peer was accepted"
    assert cs._local_owner_ok("100.64.0.5", _H()) is False, "a shared-address-space peer was accepted"
    assert cs._local_owner_ok("127.0.0.1", _H({"X-Forwarded-For": "192.0.2.50"})) is False, (
        "a loopback peer carrying X-Forwarded-For was accepted - this is the "
        "reverse-proxy-to-loopback shape that must be refused")


def test_pair_page_served_to_a_real_loopback_caller():
    httpd, port = _start_server()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/pair")
        resp = conn.getresponse()
        status = resp.status
        body = resp.read().decode("utf-8")
        conn.close()
        assert status == 200, "a genuine loopback caller was refused GET /pair"
        assert resp.getheader("Content-Type", "").startswith("text/html")
        assert "<html" in body
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_pair_page_route_uses_the_shared_owner_only_gate():
    """A real socket test cannot fake a non-loopback peer without a second interface, so the
    refusal cases are covered by the free-function test above; this proves the route calls that
    same function at least once per request."""
    with mock.patch.object(cs, "_local_owner_ok", wraps=cs._local_owner_ok) as spy:
        httpd, port = _start_server()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/pair")
            resp = conn.getresponse()
            resp.read()
            conn.close()
        finally:
            httpd.shutdown()
            httpd.server_close()
    assert spy.call_count >= 1, "GET /pair did not route through the shared owner-only gate"


def test_pair_page_refuses_a_request_carrying_a_proxy_header():
    httpd, port = _start_server()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", "/pair", headers={"X-Forwarded-For": "192.0.2.50"})
        resp = conn.getresponse()
        status = resp.status
        resp.read()
        conn.close()
        assert status == 404, (
            "a request carrying X-Forwarded-For was served GET /pair despite connecting from "
            "loopback")
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------- QR payload
def test_qr_payload_is_exactly_address_and_name_and_nothing_else():
    payload = cs._pairing_qr_payload("http://192.0.2.10:8788", "Example laptop")
    assert payload == {"address": "http://192.0.2.10:8788", "name": "Example laptop"}
    assert set(payload.keys()) == {"address", "name"}, (
        "the QR payload must be exactly {address, name}, never a key or any other field")


def test_pairing_address_is_the_bound_lan_address_or_nothing(monkeypatch):
    monkeypatch.setattr(cs, "LAN_EXPOSED", False)
    assert cs._pairing_address() == ""
    monkeypatch.setattr(cs, "LAN_EXPOSED", True)
    monkeypatch.setattr(cs, "BIND_HOST", "192.0.2.10")
    monkeypatch.setattr(cs, "PORT", 8788)
    monkeypatch.setattr(cs, "TLS_ENABLED", False)
    assert cs._pairing_address() == "http://192.0.2.10:8788"
    monkeypatch.setattr(cs, "TLS_ENABLED", True)
    assert cs._pairing_address() == "https://192.0.2.10:8788"


def test_pair_page_generates_the_qr_from_exactly_the_shown_address_and_name(monkeypatch):
    """Asserts on the payload the generator was actually given, and that it ran exactly once
    per page build (no optical QR decoder is available here)."""
    monkeypatch.setattr(cs, "LAN_EXPOSED", True)
    monkeypatch.setattr(cs, "BIND_HOST", "192.0.2.10")
    monkeypatch.setattr(cs, "PORT", 8788)
    monkeypatch.setattr(cs, "TLS_ENABLED", False)
    monkeypatch.setenv("ARROWBRIDGE_DEVICE_NAME", "Example laptop")
    with mock.patch.object(cs, "_pairing_qr_svg_data_uri",
                            wraps=cs._pairing_qr_svg_data_uri) as spy:
        html_out = cs._pair_page_html()
    assert spy.call_count == 1, "the QR generator was called more than once for one page build"
    (payload_arg,), _kwargs = spy.call_args
    assert payload_arg == {"address": "http://192.0.2.10:8788", "name": "Example laptop"}, (
        "the QR generator was not given exactly the address and name the page shows")
    assert "data:image/svg+xml;base64," in html_out, "the page has no embedded QR image"
    assert "192.0.2.10:8788" in html_out and "Example laptop" in html_out


def test_pair_page_has_no_qr_when_bound_to_loopback(monkeypatch):
    monkeypatch.setattr(cs, "LAN_EXPOSED", False)
    html_out = cs._pair_page_html()
    assert "data:image/svg+xml;base64," not in html_out, (
        "a QR was embedded on a loopback bind - there is no address a phone could reach")
    assert "ARROWBRIDGE_BIND" in html_out


# ---------------------------------------------------------------- no secret in the page source
def test_page_source_carries_no_pairing_key_or_digits(monkeypatch):
    monkeypatch.setattr(cs, "LAN_EXPOSED", True)
    monkeypatch.setattr(cs, "BIND_HOST", "192.0.2.10")
    html_out = cs._pair_page_html()
    assert cs.PAIR_KEY not in html_out, "the pairing key leaked into the page source"
    # The four-digit code only ever arrives from /pair-status at runtime; the freshly built page
    # must not contain a plausible placeholder standing in for a real one.
    assert "7419" not in html_out and "7 4 1 9" not in html_out, (
        "a literal placeholder code leaked into the static page source")


# ---------------------------------------------------------------- the words a person reads
_PAGE_TEXT_NODES = [
    "ArrowBridge companion",
    "Running - waiting for a device to pair",
    "A phone wants to pair with this computer",
    "If this is you, check that your phone shows the same four digits, then confirm here.",
    "Yes, that's my phone",
    "Not me",
    "Why this asks twice",
    "Waiting for the phone to confirm too",
    "Pairing finishes once both sides agree - not before.",
    "Nothing paired",
    "Back to waiting",
]


def test_page_carries_every_state_the_owner_can_see(monkeypatch):
    monkeypatch.setattr(cs, "LAN_EXPOSED", True)
    monkeypatch.setattr(cs, "BIND_HOST", "192.0.2.10")
    html_out = cs._pair_page_html()
    missing = [t for t in _PAGE_TEXT_NODES if t not in html_out]
    assert not missing, "text missing from the served page: %r" % missing


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
