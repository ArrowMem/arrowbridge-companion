"""mDNS advertisement, so a client on the same local network can find this companion by name
instead of a human typing an address.

Discovery finds the address, never the key. mDNS TXT records are broadcast in cleartext to every
device on the network, the same as every printer and media player already does, so the record
carries only a display name and whether pairing is required. Nothing sensitive may ever be put
here.

Service type: _arrowbridge._tcp.local. (the leading underscores are DNS-SD convention, RFC 6763).

mDNS does not cross a router, a VPN, or a mesh network. This helps on the one physical network
the phone and the machine share, which is the whole scope of this program.

ponytail: this module only ever ADVERTISES. Browsing is the client's job.
"""

import ipaddress
import logging
import os
import socket

logger = logging.getLogger("companion.discovery")

SERVICE_TYPE = "_arrowbridge._tcp.local."

# Addresses that must never appear in the A-record this advertises. Loopback and link-local are
# noise nobody on the Wi-Fi can use. 100.64.0.0/10 is the shared address space of RFC 6598, used
# by carrier NAT and by some VPN meshes for their virtual addresses: a phone on the Wi-Fi cannot
# reach it, and this machine should not broadcast it.
_EXCLUDED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)


def _filter_lan_addresses(addresses):
    """Pure filter, no adapter enumeration, so a test can drive it with a synthetic list."""
    out = []
    for addr in addresses:
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        if any(parsed in net for net in _EXCLUDED_NETWORKS):
            continue
        out.append(addr)
    return out


def _local_lan_addresses():
    """Every local IPv4 address a phone on the same physical network could plausibly reach.
    Uses `ifaddr` directly: zeroconf's own `get_all_addresses()` is deprecated in the pinned
    version and returned loopback, link-local and VPN addresses unfiltered."""
    import ifaddr

    found = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if ip.is_IPv4:
                found.append(ip.ip)
    return _filter_lan_addresses(found)


def _default_device_name():
    """A human-recognizable label for the found-device list on the phone. Never the pairing key
    or anything else secret. Falls back to the OS hostname."""
    configured = os.environ.get("ARROWBRIDGE_DEVICE_NAME", "").strip()
    return configured or socket.gethostname()


def build_service_info(port, pair_required):
    """The zeroconf ServiceInfo this companion advertises, on every LAN-reachable local IPv4
    address (a machine with Wi-Fi and Ethernet both up is discoverable on whichever one the phone
    is on). `zeroconf` is imported here, not at module load: a loopback-only run never needs it
    installed."""
    from zeroconf import ServiceInfo

    name = _default_device_name()
    addresses = _local_lan_addresses()
    if not addresses:
        raise RuntimeError("no LAN-reachable local IPv4 address found to advertise on")
    properties = {
        # Non-secret only. Anyone on the same Wi-Fi can read a TXT record.
        "name": name,
        "pair_required": "1" if pair_required else "0",
    }
    return ServiceInfo(
        SERVICE_TYPE,
        name=f"{name}.{SERVICE_TYPE}",
        addresses=[socket.inet_aton(a) for a in addresses],
        port=port,
        properties=properties,
        server=f"{socket.gethostname()}.local.",
    )


class Advertiser:
    """Owns the zeroconf instance and the one ServiceInfo this companion publishes, so the
    server can start it only when LAN-bound and stop it cleanly on shutdown. An mDNS responder
    that outlives the HTTP server it describes would keep advertising a dead service."""

    def __init__(self):
        self._zc = None
        self._info = None

    def start(self, port, pair_required=True):
        if self._zc is not None:
            return  # already advertising; a double-start is a caller bug, not a reason to crash
        from zeroconf import Zeroconf

        self._info = build_service_info(port, pair_required)
        self._zc = Zeroconf()
        self._zc.register_service(self._info)
        logger.info("mDNS advertising as %r on %s (same physical network only)",
                    self._info.name, SERVICE_TYPE)

    def stop(self):
        if self._zc is None:
            return
        try:
            self._zc.unregister_service(self._info)
        finally:
            self._zc.close()
            self._zc = None
            self._info = None
