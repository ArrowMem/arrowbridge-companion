"""Checks for mDNS discovery (discovery.py).

Each check advertises a real service and browses for it with a real zeroconf client in the same
process, not a mock of either side. Requires `zeroconf` and a LAN-reachable IPv4 adapter. If
another ArrowBridge companion is advertising on your network while this runs, the browse can find
it too and the single-result assertions will say so.

Run:  python -m pytest -q test_discovery.py
"""

import ipaddress
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from discovery import (  # noqa: E402
    Advertiser, SERVICE_TYPE, build_service_info, _filter_lan_addresses, _EXCLUDED_NETWORKS)


def _browse_once(timeout=5.0):
    """Browses for SERVICE_TYPE and returns the (name, info) pairs actually resolved within
    `timeout` seconds. If the Advertiser never put a packet on the wire, this is empty and the
    check fails for real."""
    from zeroconf import Zeroconf, ServiceBrowser

    found = {}

    class _Listener:
        def add_service(self, zc, type_, name):
            info = zc.get_service_info(type_, name, timeout=2000)
            if info:
                found[name] = info

        def update_service(self, zc, type_, name):
            pass

        def remove_service(self, zc, type_, name):
            found.pop(name, None)

    zc = Zeroconf()
    try:
        ServiceBrowser(zc, SERVICE_TYPE, _Listener())
        deadline = time.time() + timeout
        while time.time() < deadline and not found:
            time.sleep(0.1)
        return dict(found)
    finally:
        zc.close()


def test_advertised_service_is_actually_discoverable():
    adv = Advertiser()
    adv.start(port=18788, pair_required=True)
    try:
        found = _browse_once()
        assert found, "no ArrowBridge service was discovered on the network at all"
        (info,) = found.values()
        assert info.port == 18788, f"discovered port {info.port} != the one actually advertised"
    finally:
        adv.stop()


def test_pairing_key_never_appears_in_the_txt_record():
    """build_service_info takes no key parameter at all; this scans the actual advertised
    properties for anything that looks like a secret, so a future edit that threads a key
    through cannot pass silently."""
    info = build_service_info(port=18788, pair_required=True)
    for key, value in info.properties.items():
        key_s = key.decode() if isinstance(key, bytes) else key
        val_s = value.decode() if isinstance(value, bytes) else str(value)
        assert key_s in ("name", "pair_required"), f"unexpected TXT field: {key_s!r}"
        assert len(val_s) < 64 or key_s == "name", (
            f"suspiciously long value in TXT field {key_s!r}, a pairing key would look exactly "
            f"like this")


def test_noise_and_vpn_addresses_never_reach_the_advertisement():
    """A shared-address-space (100.64.0.0/10) address, link-local noise and loopback must all be
    filtered out; the one real LAN address must survive."""
    synthetic = [
        "100.64.0.5",       # RFC 6598 shared address space, used by some VPN meshes
        "169.254.0.64", "169.254.153.59", "169.254.226.80",  # link-local noise
        "127.0.0.1",        # loopback
        "192.0.2.10",       # the one real LAN address, must survive
    ]
    result = _filter_lan_addresses(synthetic)
    assert result == ["192.0.2.10"], f"expected only the real LAN address, got {result}"

    info = build_service_info(port=18791, pair_required=True)
    # The real adapter-enumerating path on THIS machine: nothing in an excluded range.
    for packed in info.addresses:
        addr = ipaddress.ip_address(socket.inet_ntoa(packed))
        assert not any(addr in net for net in _EXCLUDED_NETWORKS), (
            f"excluded-range address reached the advertisement: {addr}")


def test_service_stops_advertising_when_the_companion_stops():
    """An Advertiser that forgot to unregister would leave a stale entry answering queries for a
    companion that is no longer running."""
    adv = Advertiser()
    adv.start(port=18789, pair_required=True)
    assert _browse_once(), "setup failed: never became discoverable in the first place"
    adv.stop()
    # Zeroconf can take a moment to propagate the goodbye packet.
    time.sleep(1.0)
    found_after_stop = _browse_once(timeout=2.0)
    assert not found_after_stop, "service still discoverable after stop() was called"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
