"""One module per capability. ``ALL_CHECKS`` runs in this order (ordering
must come after relationships, because it reuses their findings)."""

from . import (exposure, inspection, internet, logtraffic, ordering, permissive,
               relationships, services, trust, usage)

ALL_CHECKS = (
    relationships.check,   # 1-3: shadowing, partial overlap, duplicates, redundancy
    trust.check,           # inappropriate trust relationships
    permissive.check,      # 4: overly permissive source/destination
    services.check,        # 5: excessive service exposure
    inspection.check,      # 6: missing UTM inspection
    internet.check,        # 7: unrestricted internet access
    logtraffic.check,      # 8: no logging
    usage.check,           # 3: unused / disabled / dead policies (hit counts)
    ordering.check,        # 9: ordering suggestions
    exposure.check,        # 10: exposure risk score
)
