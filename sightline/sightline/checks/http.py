"""Web server exposure checks (safe GET requests only)."""

from __future__ import annotations

import re

from sightline.checks import CheckContext, CheckInfo, service_check
from sightline.models import Finding, Service
from sightline.netscan import HttpResponse, http_get


def is_web(s: Service) -> bool:
    return s.name in ("http", "https", "elasticsearch") or (s.tls and s.name == "tls")


async def fetch(svc: Service, ctx: CheckContext, path: str) -> HttpResponse | None:
    key = ("http", svc.host, svc.port, path)
    if key not in ctx.cache:
        ctx.cache[key] = await http_get(
            svc.host, svc.port, path, tls=svc.tls, timeout=ctx.timeout, vhost=ctx.hostname
        )
    return ctx.cache[key]


def _not_html(resp: HttpResponse) -> bool:
    head = resp.body.lstrip()[:200].lower()
    return not head.startswith(("<!doctype", "<html", "<head", "<?xml"))


@service_check(
    is_web,
    id="WEB-GIT-EXPOSED",
    title="Git repository exposed on web server",
    severity="high",
    category="network",
    description="The site's .git directory is downloadable. Attackers can reconstruct the full "
    "source code and history, which often contains credentials and API keys.",
    remediation="Block access to /.git (e.g. 'location ~ /\\.git { deny all; }' in nginx) and "
    "deploy without the .git directory. Rotate any secrets that were committed.",
)
async def git_exposed(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/.git/HEAD")
    if not resp or resp.status != 200:
        return []
    body = resp.body.strip()
    if body.startswith("ref: refs/") or re.fullmatch(r"[0-9a-f]{40}", body):
        return [info.finding(svc.host, port=svc.port, evidence=f"GET /.git/HEAD -> {body[:60]}")]
    return []


_ENV_LINE = re.compile(r"^[A-Z][A-Z0-9_]{2,}=.*$", re.M)
_SECRET_HINT = re.compile(r"(PASS|SECRET|KEY|TOKEN|DATABASE_URL|DB_)", re.I)


@service_check(
    is_web,
    id="WEB-ENV-EXPOSED",
    title="Environment file (.env) with secrets exposed",
    severity="critical",
    category="network",
    description="The application's .env file is publicly downloadable. These files typically "
    "contain database passwords, API keys and signing secrets.",
    remediation="Block access to dotfiles at the web server, move .env outside the web root, "
    "and rotate every credential it contains.",
)
async def env_exposed(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/.env")
    if not resp or resp.status != 200 or not _not_html(resp):
        return []
    lines = _ENV_LINE.findall(resp.body)
    if len(lines) < 2 or not any(_SECRET_HINT.search(line.split("=", 1)[0]) for line in lines):
        return []
    keys = [line.split("=", 1)[0] for line in lines][:6]
    return [info.finding(svc.host, port=svc.port, evidence=f"GET /.env -> keys: {', '.join(keys)}")]


@service_check(
    is_web,
    id="WEB-DIR-LISTING",
    title="Directory listing enabled",
    severity="medium",
    category="network",
    description="The web server lists directory contents, revealing files (backups, configs, "
    "uploads) that were never meant to be linked.",
    remediation="Disable auto-indexing (Apache: Options -Indexes; nginx: autoindex off).",
)
async def dir_listing(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/")
    if not resp or resp.status != 200:
        return []
    if re.search(r"<title>\s*(Index of /|Directory listing for /)", resp.body, re.I):
        return [info.finding(svc.host, port=svc.port, evidence="GET / returned an auto-generated index")]
    return []


@service_check(
    is_web,
    id="WEB-SERVER-STATUS",
    title="Apache server-status page exposed",
    severity="medium",
    category="network",
    description="mod_status reveals every URL being requested, client IPs and server internals.",
    remediation="Restrict /server-status to localhost or admin networks (Require local).",
)
async def server_status(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/server-status")
    if resp and resp.status == 200 and "Apache Server Status" in resp.body:
        return [info.finding(svc.host, port=svc.port, evidence="GET /server-status -> 200")]
    return []


@service_check(
    is_web,
    id="WEB-PHPINFO",
    title="phpinfo() page exposed",
    severity="medium",
    category="network",
    description="A phpinfo page discloses PHP configuration, environment variables (sometimes "
    "secrets), file paths and module versions.",
    remediation="Delete the phpinfo file from the web root.",
)
async def phpinfo(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    for path in ("/phpinfo.php", "/info.php"):
        resp = await fetch(svc, ctx, path)
        if resp and resp.status == 200 and "PHP Version" in resp.body and "phpinfo" in resp.body.lower():
            return [info.finding(svc.host, port=svc.port, evidence=f"GET {path} -> phpinfo output")]
    return []


@service_check(
    is_web,
    id="WEB-ACTUATOR-ENV",
    title="Spring Boot actuator /env endpoint exposed",
    severity="high",
    category="network",
    description="The actuator environment endpoint reveals configuration properties and can "
    "leak credentials; some setups also allow modifying them.",
    remediation="Expose only health/info (management.endpoints.web.exposure.include=health,info) "
    "and protect the management port.",
)
async def actuator_env(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/actuator/env")
    if resp and resp.status == 200 and ('"propertySources"' in resp.body or '"activeProfiles"' in resp.body):
        return [info.finding(svc.host, port=svc.port, evidence="GET /actuator/env -> 200 JSON")]
    return []


@service_check(
    lambda s: is_web(s) and s.product == "Jenkins",
    id="WEB-JENKINS-SCRIPT",
    title="Jenkins script console accessible without login",
    severity="critical",
    category="network",
    description="The Jenkins script console runs arbitrary Groovy code on the controller. "
    "Unauthenticated access means remote code execution.",
    remediation="Enable Jenkins security (Manage Jenkins > Security) with real authentication "
    "and matrix-based authorization.",
)
async def jenkins_script(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/script")
    if resp and resp.status == 200 and "Script Console" in resp.body:
        return [info.finding(svc.host, port=svc.port, evidence="GET /script -> 200 Script Console")]
    return []


@service_check(
    lambda s: s.name == "http" and not s.tls,
    id="WEB-BASIC-AUTH-CLEARTEXT",
    title="Login over unencrypted HTTP (Basic authentication)",
    severity="medium",
    category="network",
    description="The server asks for HTTP Basic credentials over plain HTTP, so passwords are "
    "sent base64-encoded in cleartext.",
    remediation="Serve the site over HTTPS only and redirect HTTP to HTTPS.",
)
async def basic_cleartext(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/")
    if resp and resp.status == 401 and "basic" in resp.header("www-authenticate").lower():
        realm = resp.header("www-authenticate")
        return [info.finding(svc.host, port=svc.port, evidence=f"401 WWW-Authenticate: {realm[:80]}")]
    return []


@service_check(
    lambda s: is_web(s) and s.tls,
    id="WEB-HSTS-MISSING",
    title="HTTPS site does not set Strict-Transport-Security",
    severity="low",
    category="network",
    description="Without HSTS, browsers may be downgraded to HTTP by a network attacker.",
    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'.",
)
async def hsts_missing(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/")
    if resp and 200 <= resp.status < 400 and not resp.header("strict-transport-security"):
        return [info.finding(svc.host, port=svc.port, evidence=f"GET / -> {resp.status}, no HSTS header")]
    return []


_APACHE_RE = re.compile(r"Apache/2\.4\.(49|50)\b")


@service_check(
    is_web,
    id="WEB-APACHE-TRAVERSAL",
    title="Apache HTTP Server 2.4.49/2.4.50 path traversal and RCE",
    severity="critical",
    category="network",
    description="These Apache releases allow path traversal outside the document root and, "
    "with CGI enabled, remote code execution. Both are on CISA's KEV list.",
    remediation="Upgrade Apache httpd to 2.4.51 or later immediately.",
    references=[
        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-42013",
    ],
)
async def apache_traversal(info: CheckInfo, svc: Service, ctx: CheckContext) -> list[Finding]:
    resp = await fetch(svc, ctx, "/")
    server = resp.header("server") if resp else ""
    if not _APACHE_RE.search(server):
        return []
    return [info.finding(svc.host, port=svc.port, cves=["CVE-2021-41773", "CVE-2021-42013"],
                         confidence="likely", kev=True, evidence=f"Server: {server}")]  # fmt: skip
