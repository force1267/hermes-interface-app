"""N01/N02 backend-only egress, default deny."""
import ipaddress
from urllib.parse import urlparse


class EgressError(ValueError):
    pass


PAGE_DIRECT_OPS = {"fetch", "external_media", "form_submit", "navigate", "websocket"}


def request_page_egress(op, caps=()):
    """N01: pages have no separate connection. Always denied, caps or not."""
    if op in PAGE_DIRECT_OPS or True:
        raise EgressError(f"page-egress-denied:{op}")


def direct_page_operation(op):
    if op in PAGE_DIRECT_OPS:
        raise EgressError(f"page-direct-denied:{op}")
    raise EgressError(f"page-egress-denied:{op}")


def _origin_of(url):
    p = urlparse(url)
    if not p.scheme or not p.hostname:
        raise EgressError("destination-unparseable")
    port = p.port or (443 if p.scheme == "https" else 80)
    return (p.scheme.lower(), p.hostname.lower(), port)


def _is_private_host(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        h = host.lower()
        return h in ("localhost",) or h.endswith(".local") or h.endswith(".internal")


class ConnectorStore:
    """N02 backend connectors. Default deny; explicit policy only."""

    def __init__(self):
        self._recs = {}

    def upsert(self, record):
        for f in ("connector_id", "owner_api", "enabled", "allowed_operations",
                  "allowed_origins", "revision"):
            if f not in record:
                raise EgressError(f"connector-missing: {f}")
        self._recs[record["connector_id"]] = dict(record)

    def remove(self, connector_id):
        self._recs.pop(connector_id, None)

    def authorize(self, connector_id, operation, destination,
                  principal_api=None, dest_source="server", redirect_chain=()):
        rec = self._recs.get(connector_id)
        if rec is None or not rec.get("enabled"):
            raise EgressError("connector-denied")
        if dest_source == "fragment":
            raise EgressError("fragment-destination-denied")
        if operation not in rec.get("allowed_operations", []):
            raise EgressError("operation-denied")
        if principal_api is not None and principal_api != rec.get("owner_api"):
            raise EgressError("principal-scope-denied")
        want = _origin_of(destination)
        allowed = rec.get("allowed_origins", [])
        ok = False
        for a in allowed:
            try:
                if _origin_of(a) == want:
                    ok = True
            except EgressError:
                continue
        if not ok:
            raise EgressError("destination-denied")
        for hop in redirect_chain:
            hop_o = _origin_of(hop)
            if not any(_origin_of(a) == hop_o for a in allowed):
                raise EgressError("redirect-denied")
            if _is_private_host(hop_o[1]) and not rec.get("allow_private"):
                raise EgressError("private-destination-denied")
        if _is_private_host(want[1]) and not rec.get("allow_private"):
            raise EgressError("private-destination-denied")
        return True
