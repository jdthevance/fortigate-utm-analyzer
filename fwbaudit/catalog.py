"""Catalogue of FortiWeb functions and how the audit treats each one.

JayDee asked for every FortiWeb function to be audited. Most protection
features are separate objects (``config waf ...``) that a web protection
profile switches on by name, so one table can drive three generic checks for
all of them:

1. **Coverage**: is the feature switched on in the profiles that live server
   policies use? Missing *core* features are findings; missing *recommended*
   ones are listed together; *situational* ones only appear in the coverage
   table, because whether they are needed depends on the application.
2. **Broken references**: a profile names an object that does not exist.
3. **Detect-only actions**: the object exists but every action is ``alert``,
   so attacks are logged and still reach the server.

Features with deeper rules (signatures, TLS, DoS, bots ...) also have their
own check module; ``depth`` says which, so the report can show how far each
function is audited. ``depth = "runtime"`` marks functions whose quality
depends on live state (learning models, signature versions) that a config
backup cannot show.

Source: FortiWeb 8.0 CLI Reference, ``waf web-protection-profile
inline-protection`` and the command pages it links to.

Go mapping: ``internal/fortiweb/catalog`` (a static ``[]Feature`` table).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

CORE, RECOMMENDED, SITUATIONAL = "core", "recommended", "situational"


@dataclass(frozen=True)
class Feature:
    key: str                 # setting in the protection profile ("" = not profile-based)
    blocks: Tuple[str, ...]  # CLI blocks that define the object
    name: str
    area: str                # report category
    level: str               # core / recommended / situational
    depth: str               # deep / generic / runtime
    why: str


F = Feature
PROFILE_FEATURES: Tuple[Feature, ...] = (
    F("signature-rule", ("waf signature",), "Attack signatures", "Signatures", CORE, "deep",
      "Blocks SQL injection, XSS, generic attacks, known exploits, trojans and data leaks."),
    F("HTTP-protocol-parameter-restriction", ("waf HTTP-protocol-parameter-restriction",),
      "HTTP protocol constraints", "Web protection profiles", CORE, "deep",
      "Rejects malformed and oversized requests (smuggling, header and parameter abuse)."),
    F("application-layer-dos-prevention", ("waf application-layer-dos-prevention",),
      "Application DoS prevention", "DoS protection", CORE, "deep",
      "Limits request and connection floods per client and per session."),
    F("ip-intelligence", (), "IP reputation (FortiGuard)", "Web protection profiles",
      CORE, "deep", "Drops requests from known botnets, anonymous proxies, phishing and spam sources."),
    F("bot-mitigate-policy", ("waf bot-mitigate-policy",), "Bot mitigation", "Bot mitigation", CORE, "deep",
      "Known bad bots, scanners and scrapers (known-bots, threshold and biometrics detection)."),
    F("advanced-bot-protection", ("waf advanced-bot-protection",), "Advanced bot protection (cloud)",
      "Bot mitigation", SITUATIONAL, "generic", "FortiGuard cloud bot protection; alternative to bot-mitigate-policy."),
    F("syntax-based-attack-detection", ("waf syntax-based-attack-detection",),
      "Syntax-based SQLi/XSS detection", "Signatures", RECOMMENDED, "generic",
      "Parses SQL and JavaScript syntax to catch injections that evade signatures."),
    F("allow-method-policy", ("waf allow-method-policy",), "Allowed HTTP methods", "Access & input rules",
      RECOMMENDED, "deep", "Rejects TRACE, CONNECT, WebDAV and other methods the application does not use."),
    F("cookie-security-policy", ("waf cookie-security",), "Cookie security", "Web protection profiles",
      RECOMMENDED, "deep", "Signs or encrypts cookies and adds Secure/HttpOnly to stop tampering and theft."),
    F("HTTP-header-security", ("waf http-header-security",), "HTTP security headers", "Web protection profiles",
      RECOMMENDED, "deep", "Adds X-Frame-Options, X-Content-Type-Options, CSP and similar browser protections."),
    F("file-upload-policy", ("waf file-upload-restriction-policy",), "File upload restriction and AV",
      "Web protection profiles", RECOMMENDED, "deep",
      "Limits upload types and sizes and scans uploads for malware (AV, FortiSandbox, ICAP)."),
    F("x-forwarded-for-rule", ("waf x-forwarded-for",), "X-Forwarded-For / real client IP",
      "Client IP & X-Forwarded-For", RECOMMENDED, "deep",
      "Finds the real client behind a proxy or NAT device, and passes it to the servers."),
    F("ip-list-policy", ("waf ip-list",), "IP allow/block lists", "Access & input rules", SITUATIONAL, "deep",
      "Trusted, blocked and allow-only client addresses."),
    F("geo-block-list-policy", ("waf geo-block-list",), "Geo IP blocking", "Access & input rules",
      SITUATIONAL, "generic", "Blocks countries the application does not serve."),
    F("url-access-policy", ("waf url-access url-access-policy",), "URL access rules", "Access & input rules",
      SITUATIONAL, "generic", "Restricts admin paths and other URLs to allowed sources."),
    F("custom-access-policy", ("waf custom-access policy",), "Custom access (combination) rules",
      "Access & input rules", SITUATIONAL, "generic", "Combines source, URL, header and rate conditions."),
    F("parameter-validation-rule", ("waf parameter-validation-rule",), "Input (parameter) validation",
      "Access & input rules", SITUATIONAL, "generic", "Positive security model for form and query parameters."),
    F("hidden-fields-protection", ("waf hidden-fields-protection",), "Hidden field protection",
      "Access & input rules", SITUATIONAL, "generic", "Stops tampering with hidden form fields."),
    F("csrf-protection", ("waf csrf-protection",), "CSRF protection", "Web protection profiles",
      SITUATIONAL, "generic", "Adds tokens to stop cross-site request forgery."),
    F("padding-oracle", ("waf padding-oracle",), "Padding oracle protection", "Web protection profiles",
      SITUATIONAL, "generic", "Protects encrypted cookies and parameters against padding oracle attacks."),
    F("user-tracking-policy", ("waf user-tracking policy",), "User tracking", "Web protection profiles",
      SITUATIONAL, "generic", "Ties attacks to user names, and detects session fixation."),
    F("mitb-protection", ("waf mitb-policy",), "Man-in-the-browser protection", "Web protection profiles",
      SITUATIONAL, "generic", "Detects form tampering by browser malware."),
    F("client-side-protection-policy", ("waf client-side-protection-policy",), "Client-side (JavaScript) protection",
      "Web protection profiles", SITUATIONAL, "generic", "Watches third-party scripts (Magecart-style skimming)."),
    F("subresource-integrity-policy", ("waf subresource-integrity-policy",), "Subresource integrity",
      "Web protection profiles", SITUATIONAL, "generic", "Adds integrity hashes to scripts loaded from other sites."),
    F("url-encryption-policy", ("waf url-encryption url-encryption-policy",), "URL encryption",
      "Web protection profiles", SITUATIONAL, "generic", "Hides real URLs from clients."),
    F("openapi-validation-policy", ("waf openapi-validation-policy",), "OpenAPI schema validation",
      "API protection", SITUATIONAL, "generic", "Checks API calls against the published OpenAPI schema."),
    F("json-validation-policy", ("waf json-validation rule", "waf json-validation policy"),
      "JSON validation", "API protection", SITUATIONAL, "generic", "Schema and size limits for JSON bodies."),
    F("api-management-policy", ("waf api-policy",), "API gateway (keys and rate limits)", "API protection",
      SITUATIONAL, "generic", "API key checks and per-user rate limits."),
    F("mobile-api-protection", ("waf mobile-api-protection-policy", "waf mobile-api-protection-rule"),
      "Mobile API protection", "API protection", SITUATIONAL, "generic", "JWT checks for mobile app traffic."),
    F("websocket-security-policy", ("waf websocket-security policy",), "WebSocket security", "API protection",
      SITUATIONAL, "generic", "Inspects WebSocket frames."),
    F("cors-protection-policy", ("waf cors-protection-policy",), "CORS protection", "API protection",
      SITUATIONAL, "generic", "Enforces allowed cross-origin callers."),
    F("site-publisher-helper", ("waf site-publish-helper policy",), "Site publishing / SSO",
      "Authentication", SITUATIONAL, "deep", "Pre-authentication and single sign-on in front of the application."),
    F("url-rewrite-policy", ("waf url-rewrite url-rewrite-policy",), "URL rewriting", "Web protection profiles",
      SITUATIONAL, "generic", "Rewrites requests and responses (not a protection by itself)."),
    F("file-compress-rule", ("waf file-compress-rule",), "Compression", "Web protection profiles",
      SITUATIONAL, "generic", "Performance feature."),
    F("threat-score-profile", ("server-policy pattern threat-score-profile",), "Threat scoring",
      "Web protection profiles", SITUATIONAL, "generic", "Blocks clients whose combined low-level violations add up."),
    F("file-list-policy", ("waf file-list",), "File list policy", "Web protection profiles",
      SITUATIONAL, "generic", "Allow or deny lists of file names."),
)

# Functions that are not switched on through a protection profile.
OTHER_FEATURES: Tuple[Feature, ...] = (
    F("", ("waf machine-learning-policy",), "Machine-learning anomaly detection", "Machine learning",
      RECOMMENDED, "runtime", "Learns normal parameter values per domain and blocks anomalies."),
    F("", ("waf bot-detection-policy",), "Machine-learning bot detection", "Bot mitigation", SITUATIONAL,
      "runtime", "Learns normal client behaviour per server policy."),
    F("", ("waf api-learning-policy",), "API discovery (learning)", "API protection", SITUATIONAL, "runtime",
      "Learns API endpoints from traffic."),
    F("", ("waf webshell-detection-policy",), "Web shell detection", "Web protection profiles", SITUATIONAL,
      "generic", "Detects web shells in uploads."),
    F("", ("waf waiting-room-policy",), "Waiting room", "DoS protection", SITUATIONAL, "generic",
      "Queues visitors when the site is overloaded."),
    F("", ("server-policy health",), "Server health checks", "Server pools & health checks", RECOMMENDED,
      "deep", "Takes failed servers out of the pool."),
    F("", ("server-policy persistence-policy",), "Session persistence", "Server pools & health checks",
      SITUATIONAL, "generic", "Keeps a client on one server."),
    F("", ("server-policy allow-hosts",), "Protected host names", "Server policies", RECOMMENDED, "deep",
      "Accepts only the Host: names the application really serves."),
    F("", ("server-policy ztna-profile",), "ZTNA", "Authentication", SITUATIONAL, "generic",
      "Zero-trust access tags from FortiClient EMS."),
    F("", ("user ldap-user", "user radius-user", "user tacacs+-user", "user saml-user", "user pki-user"),
      "Authentication servers", "Authentication", SITUATIONAL, "deep", "LDAP, RADIUS, TACACS+, SAML, certificates."),
    F("", ("wvs profile", "wvs policy"), "Web vulnerability scanner", "Updates & integrations", SITUATIONAL,
      "runtime", "Scans the protected sites; results are not in the config."),
    F("", ("waf ftp-protection-profile",), "FTP protection", "Server policies", SITUATIONAL, "generic",
      "FTP command and file checks."),
    F("", ("system antivirus", "system fortisandbox", "system icapserver"), "Malware scanning back ends",
      "Updates & integrations", SITUATIONAL, "deep", "AV database, FortiSandbox and ICAP used by upload scanning."),
    F("", ("system ha",), "High availability", "High availability", RECOMMENDED, "deep",
      "A second unit keeps the WAF in the path when one fails."),
    F("", ("system autoupdate schedule", "waf signature_update_policy"), "FortiGuard updates",
      "Updates & integrations", CORE, "deep", "Keeps signatures, IP reputation and AV current."),
    F("", ("system backup",), "Scheduled configuration backup", "Updates & integrations", RECOMMENDED,
      "deep", "Off-box configuration backups."),
    F("", ("system fortigate-integration",), "FortiGate quarantine integration", "Updates & integrations",
      SITUATIONAL, "deep", "Blocks clients that FortiGate has quarantined."),
    F("", ("system csf",), "Security Fabric", "Updates & integrations", SITUATIONAL, "generic",
      "Joins the FortiGate Security Fabric."),
    F("", ("system sdn-connector", "system external-resource"), "Cloud connectors and threat feeds",
      "Updates & integrations", SITUATIONAL, "deep", "Dynamic server addresses and external IP lists."),
    F("", ("system automation-stitch",), "Automation stitches", "Updates & integrations", SITUATIONAL,
      "generic", "Scripts and emails triggered by events."),
    F("", ("system certificate letsencrypt", "system certificate ocsp-stapling", "system certificate verify"),
      "Certificate services", "TLS & certificates", SITUATIONAL, "deep",
      "Let's Encrypt renewal, OCSP stapling, client-certificate checks."),
    F("", ("system fips-cc",), "FIPS / Common Criteria mode", "System & admin access", SITUATIONAL, "generic",
      "Restricts crypto to certified algorithms."),
)

ALL_FEATURES = PROFILE_FEATURES + OTHER_FEATURES
BY_KEY = {f.key: f for f in PROFILE_FEATURES}

# Values of ``action`` settings that let the request through.
DETECT_ONLY = {"alert", "pass", "continue", "bypass"}
NO_LOG = {"deny_no_log"}
