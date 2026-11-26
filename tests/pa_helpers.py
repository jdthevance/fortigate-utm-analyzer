"""Small helpers for building test configs (policy analysis tests)."""

import random


def block(name, entries):
    """entries: list of (edit_name, {key: value-string})"""
    out = ["config " + name]
    for ident, settings in entries:
        out.append("    edit {}".format(ident if str(ident).isdigit() else '"{}"'.format(ident)))
        for k, v in settings.items():
            out.append("        set {} {}".format(k, v))
        out.append("    next")
    out.append("end")
    return "\n".join(out)


def q(*names):
    return " ".join('"{}"'.format(n) for n in names)


INTERFACES = block("system interface", [
    ("wan1", {"ip": "203.0.113.2 255.255.255.0", "role": "wan"}),
    ("lan", {"ip": "10.1.0.1 255.255.0.0", "role": "lan"}),
    ("dmz", {"ip": "10.10.10.1 255.255.255.0", "role": "dmz"}),
    ("guest", {"ip": "172.30.0.1 255.255.255.0"}),
])


def policy(pid, src="lan", dst="dmz", sa="all", da="all", svc="ALL", action="accept", **extra):
    s = {"srcintf": q(src), "dstintf": q(dst), "srcaddr": sa, "dstaddr": da,
         "action": action, "schedule": '"always"', "service": svc, "logtraffic": "all"}
    s.update(extra)
    return (pid, s)


def random_config(n, seed=1, broad_every=0):
    """A rule base with real overlaps: random /16-/32 subnets and port mixes."""
    rnd = random.Random(seed)
    addrs, svcs, pols = [], [], []
    for i in range(max(50, n // 5)):
        plen = rnd.choice([16, 20, 24, 24, 28, 32, 32])
        a, b = rnd.randint(0, 3), rnd.randint(0, 255)
        addrs.append(("net{}".format(i), {"subnet": "10.{}.{}.0/{}".format(a, b, plen)
                                          if plen <= 24 else "10.{}.{}.{} 255.255.255.255".format(a, b, rnd.randint(1, 254))}))
    for i in range(30):
        lo = rnd.randint(1, 60000)
        svcs.append(("svc{}".format(i), {"tcp-portrange": "{}-{}".format(lo, lo + rnd.choice([0, 0, 10, 1000]))}))
    for i in range(1, n + 1):
        if broad_every and i % broad_every == 0:
            pols.append(policy(i, sa='"all"', da='"all"', svc='"ALL"', action=rnd.choice(["accept", "deny"])))
            continue
        pols.append(policy(i, src=rnd.choice(["lan", "guest"]), dst=rnd.choice(["dmz", "wan1"]),
                           sa=q(*rnd.sample([a[0] for a in addrs], rnd.choice([1, 1, 2]))),
                           da=q(*rnd.sample([a[0] for a in addrs], rnd.choice([1, 2]))),
                           svc=q(*rnd.sample([s[0] for s in svcs], rnd.choice([1, 2]))),
                           action=rnd.choice(["accept", "accept", "deny"])))
    return "\n".join([INTERFACES, block("firewall address", addrs),
                      block("firewall service custom", svcs), block("firewall policy", pols)])
