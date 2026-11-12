"""Validation for synthetic network events consumed by the simulator and detector."""
import ipaddress
import math
from collections.abc import Mapping


_DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
_EVENT_TYPES = {"login", "http", "probe", "traffic"}
_PROTOCOLS = {"TCP", "UDP", "HTTP", "SSH"}
_NUMERIC_FIELDS = {
    "t": (0, None),
    "dst_port": (1, 65535),
    "payload_len": (0, None),
    "special_ratio": (0, 1),
    "pps": (0, None),
    "duration": (0, None),
    "requests": (1, None),
}


def validate_event(event):
    """Validate one generated event and return it unchanged."""
    if not isinstance(event, Mapping):
        raise ValueError("event must be a mapping")

    required = {"t", "src_ip", "dst_port", "protocol", "event_type",
                "payload_len", "special_ratio", "pps", "duration", "requests"}
    missing = required - event.keys()
    if missing:
        raise ValueError(f"event missing required fields: {', '.join(sorted(missing))}")

    try:
        address = ipaddress.ip_address(event["src_ip"])
    except (TypeError, ValueError) as exc:
        raise ValueError("src_ip must be a valid RFC 5737 documentation address") from exc
    if address.version != 4 or not any(address in network for network in _DOCUMENTATION_NETWORKS):
        raise ValueError("src_ip must be in an RFC 5737 documentation range")
    if event["protocol"] not in _PROTOCOLS:
        raise ValueError("protocol is not supported")
    if event["event_type"] not in _EVENT_TYPES:
        raise ValueError("event_type is not supported")

    for field, (minimum, maximum) in _NUMERIC_FIELDS.items():
        value = event[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{field} must be a finite number")
        if value < minimum or (maximum is not None and value > maximum):
            raise ValueError(f"{field} is outside its valid range")
    if not isinstance(event["dst_port"], int):
        raise ValueError("dst_port must be an integer")
    if not isinstance(event["requests"], int):
        raise ValueError("requests must be an integer")
    return event
