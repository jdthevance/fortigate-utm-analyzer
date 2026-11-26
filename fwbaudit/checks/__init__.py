"""FortiWeb audit domains. Each maps to a ``fwb.py`` flag (``-sys``, ``-pol`` ...)."""

from . import clientip, logging, operations, policies, protection, signatures, system, tls

DOMAINS = {
    "sys": ("System, admin access, updates, HA and authentication", (system.check, operations.check)),
    "pol": ("Server policies, server pools and health checks", (policies.check,)),
    "tls": ("TLS and certificates", (tls.check,)),
    "sig": ("Attack signatures", (signatures.check,)),
    "wp": ("Web protection profiles and every protection feature", (protection.check,)),
    "ip": ("Real client IP (X-Forwarded-For) and trusted IP lists", (clientip.check,)),
    "log": ("Logging", (logging.check,)),
}
