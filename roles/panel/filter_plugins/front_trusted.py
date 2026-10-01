"""The front's trusted addresses of the panel (frontTrustedAddrs, SBKubric/sane-3x-ui#228, orchestrator#57).

The panel stores the list normalised (web/entity/front_trusted.go ParseFrontTrustedAddrs): entries separated by
commas, semicolons, spaces or new lines; an address in its canonical form (a v4-mapped one as plain v4, not the
unspecified address), a network masked and no wider than /16 (IPv4) or /32 (IPv6); in the order given, no repeats, at
most 64. These filters do the same on the controller, so that the role compares what it wants with what the panel
stores and refuses a bad entry before anything is written.

    {{ ['203.0.113.9/24', '2001:DB8::1'] | front_trusted_addrs }}   -> ['203.0.113.0/24', '2001:db8::1']
    {{ 'a,b' | front_trusted_addrs(source='the panel') }}            the name in an error message
    {{ ['203.0.113.0/24'] | front_trusted_covers('203.0.113.5') }}  -> True
"""

import ipaddress
import re

from ansible.errors import AnsibleFilterError

FRONT_TRUSTED_MAX = 64
MIN_BITS = {4: 16, 6: 32}
SEPARATORS = re.compile(r"[,; \t\r\n]+")


def _entries(value):
    """The entries of a string, or of a list of strings and lists (None and '' are none)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        fields = []
        for item in value:
            fields.extend(_entries(item))
        return fields
    return [e for e in SEPARATORS.split(str(value)) if e]


def _entry(field, source):
    if "/" in field:
        address, bits = field.split("/", 1)
        if not re.fullmatch(r"0|[1-9][0-9]{0,2}", bits) or "%" in address:
            raise AnsibleFilterError(f"{source}: '{field}' is neither an IP address nor a network in CIDR notation")
        try:
            net = ipaddress.ip_network(field, strict=False)
        except ValueError:
            raise AnsibleFilterError(f"{source}: '{field}' is neither an IP address nor a network in CIDR notation")
        if net.version == 6 and net.network_address.ipv4_mapped is not None:
            raise AnsibleFilterError(f"{source}: '{field}' is a v4-mapped network; write it as an IPv4 network")
        if net.prefixlen < MIN_BITS[net.version]:
            raise AnsibleFilterError(
                f"{source}: '{field}' is too wide a network: /{MIN_BITS[net.version]} at the widest for IPv{net.version}")
        return str(net)
    if "%" in field:
        raise AnsibleFilterError(f"{source}: '{field}' is neither an IP address nor a network in CIDR notation")
    try:
        addr = ipaddress.ip_address(field)
    except ValueError:
        raise AnsibleFilterError(f"{source}: '{field}' is neither an IP address nor a network in CIDR notation "
                                 "(names and host:port are refused)")
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_unspecified:
        raise AnsibleFilterError(f"{source}: '{field}' is the unspecified address")
    return str(addr)


def front_trusted_addrs(value, source="front_trusted_addrs"):
    """The list (or the string) normalised the way the panel stores it; AnsibleFilterError on a bad entry."""
    out = []
    for field in _entries(value):
        entry = _entry(field, source)
        if entry not in out:
            out.append(entry)
    if len(out) > FRONT_TRUSTED_MAX:
        raise AnsibleFilterError(f"{source}: at most {FRONT_TRUSTED_MAX} front trusted addresses, got {len(out)}")
    return out


def front_trusted_covers(value, address):
    """True when an entry of the (normalised) list is the address or a network that holds it."""
    try:
        addr = ipaddress.ip_address(str(address))
    except ValueError:
        return False
    for entry in _entries(value):
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


class FilterModule:
    def filters(self):
        return {"front_trusted_addrs": front_trusted_addrs, "front_trusted_covers": front_trusted_covers}
