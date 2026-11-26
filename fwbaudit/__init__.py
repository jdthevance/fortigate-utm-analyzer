"""FortiWeb (WAF) configuration audit, and FortiGate + FortiWeb cross-checks.

Entry point: ``python3 fwb.py -c fortiweb.conf [--fortigate fortigate.conf]``.

The FortiWeb CLI uses the same ``config / edit / set / next / end`` syntax as
FortiOS, so this package reuses the parser, VDOM scopes, finding model and
IP/port maths from ``policyaudit`` instead of copying them. Each module is
written to become one Go package in the planned rewrite:

    fwbaudit/inventory.py      -> internal/fortiweb/inventory  (typed model of the WAF config)
    fwbaudit/certs.py          -> internal/fortiweb/certs      (Go: crypto/x509 does this)
    fwbaudit/checks/*.py       -> internal/fortiweb/checks/*   (one file per audit domain)
    fwbaudit/engine.py         -> internal/fortiweb/engine     (runs the checks)
    fwbaudit/crosscheck/*.py   -> internal/crosscheck/*        (FortiGate <-> FortiWeb)
    fwbaudit/report.py         -> internal/fortiweb/report     (text, JSON, summary)
    fwbaudit/cli.py            -> cmd/fwbaudit                 (command line)

Only the Python standard library is used (Python 3.8+).
"""

__version__ = "1.0.0"

# FortiWeb CLI reference used to write the checks. Anything the reference does
# not state (for example how a plain ``show`` backup prints defaults) is marked
# "inferred" in docs/FORTIWEB_AUDIT.md.
DOCS_VERSION = "FortiWeb 8.0 CLI Reference (8.0.1 PDF, linked from the 8.0.2 online docs)"
