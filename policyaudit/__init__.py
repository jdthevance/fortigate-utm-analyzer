"""Policy analysis engine for FortiGate configuration backups.

This package is the second-generation engine behind ``utm.py -pa``. It is
written so each module maps onto one Go package in the planned rewrite:

    policyaudit/config.py    -> internal/config    (parser, VDOM scopes)
    policyaudit/netset.py    -> internal/netset    (interval sets)
    policyaudit/objects.py   -> internal/objects   (object resolver)
    policyaudit/model.py     -> internal/model     (Policy, Finding structs)
    policyaudit/hits.py      -> internal/hits      (hit-count import)
    policyaudit/checks/*.py  -> internal/checks/*  (one file per capability)
    policyaudit/engine.py    -> internal/engine    (runs checks per VDOM)
    policyaudit/report.py    -> internal/report    (text and JSON writers)
    policyaudit/cli.py       -> cmd/policyaudit    (command line)

Only the Python standard library is used, so the tool runs anywhere
Python 3.8+ is installed.
"""

__version__ = "1.0.0"
