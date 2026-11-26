#!/usr/bin/env python3
"""FortiWeb Security Analyzer.

Audits a FortiWeb 8.0 configuration backup, and with ``-fg`` also checks how
a FortiGate in front of it is connected to it (WAF bypass, exposed admin
access, NAT and client IP, TLS, inspection, routing and logging).

    python3 fwb.py -c fortiweb.conf
    python3 fwb.py -c fortiweb.conf -fg fortigate.conf --all

The code lives in the ``fwbaudit`` folder and reuses the parser, object
resolver and policy builder from ``policyaudit`` (the engine behind
``utm.py -pa``). Guide: docs/FORTIWEB_AUDIT.md.
"""

import sys

from fwbaudit.cli import main

if __name__ == "__main__":
    sys.exit(main())
