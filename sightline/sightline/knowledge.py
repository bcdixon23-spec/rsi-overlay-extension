"""Plain-language security knowledge built into the tool.

The aim is that someone who is new to security can read a Sightline report and
understand both *what* each term means and *what to do about it*, without
leaving the app. This content is surfaced in the HTML report's help panel, in
the dashboard, and by the `sightline explain` command.
"""

from __future__ import annotations

# Plain-English definitions of the jargon that appears in reports.
GLOSSARY: dict[str, str] = {
    "vulnerability": "A weakness in software or configuration that someone could misuse to break in, "
    "steal data, or disrupt a system.",
    "CVE": "Common Vulnerabilities and Exposures - a public ID for one specific known vulnerability, "
    "like CVE-2024-6387. Think of it as a catalogue number everyone uses to refer to the same flaw.",
    "CVSS": "A 0-10 score describing how severe a vulnerability is in the abstract. 9-10 is critical, "
    "7-8.9 high, 4-6.9 medium, below 4 low. It ignores your specific situation, which is why Sightline "
    "also uses the risk score below.",
    "KEV": "CISA's 'Known Exploited Vulnerabilities' list - vulnerabilities that criminals are actually "
    "using in real attacks right now. If something is on this list, patch it first.",
    "EPSS": "Exploit Prediction Scoring System - an estimate (as a percentage) of how likely a "
    "vulnerability is to be exploited in the next 30 days. High EPSS means attackers are likely to target it.",
    "risk score": "Sightline's own 0-100 number. Unlike CVSS, it factors in whether the issue is actually "
    "reachable on your network, whether a working exploit exists, and whether you can fix it today. "
    "Sort by this to decide what to do first.",
    "exposure": "Whether an attacker can actually reach the weak thing. A vulnerable library that nothing "
    "uses on the network is far less urgent than the same library behind an internet-facing service.",
    "exploit": "A piece of code or technique that turns a vulnerability into a real attack (stealing data, "
    "running commands). 'Weaponised' means a reliable, ready-made exploit is publicly available.",
    "credentialed scan": "A scan where Sightline logs into the machine (over SSH) to read exactly which "
    "software versions are installed. This is far more accurate than guessing from the outside.",
    "patch": "An update from the software vendor that fixes a vulnerability. 'Patching' means installing it.",
    "port": "A numbered door on a machine where a particular service listens - for example 22 is usually "
    "SSH, 443 is usually HTTPS. Open ports are the ways in that a scanner looks at.",
    "service": "A program listening on a port and answering requests, such as a web server or a database.",
    "TLS certificate": "The digital ID card a server presents to prove it is who it claims to be and to "
    "encrypt the connection (the padlock in your browser). Expired or weak certificates undermine that trust.",
    "end of life": "When a vendor stops releasing security updates for a product. After this date, new "
    "vulnerabilities are never fixed, so the system only gets more dangerous to run over time.",
    "packet capture": "Recording the raw traffic on a network so it can be inspected - the same idea as "
    "Wireshark. Sightline uses it to spot passwords and other secrets being sent without encryption.",
    "cleartext": "Information sent across the network without encryption, so anyone able to watch the "
    "traffic can read it. Passwords in cleartext are a serious problem.",
    "false positive": "When a scanner reports a problem that is not really there. Sightline reduces these by "
    "reading real installed versions and accounting for fixes that Linux distributions backport.",
}

# How to read the four priority buckets, in one sentence each.
PRIORITY_HELP: dict[str, str] = {
    "fix-now": "Reachable, serious, and often already being exploited. Treat these as incidents - fix today.",
    "fix-soon": "Important and worth scheduling into this week's work before they are targeted.",
    "plan": "Real issues that are lower risk right now. Put them on the backlog and fix in the normal cycle.",
    "monitor": "Minor or hard-to-exploit. Worth knowing about; fix opportunistically.",
}

MATURITY_HELP: dict[str, str] = {
    "active": "Attackers are exploiting this in the wild right now (on CISA's KEV list). Highest urgency.",
    "weaponized": "A reliable, ready-to-use public exploit exists (for example a Metasploit module).",
    "poc": "A proof-of-concept exists publicly, but it may be unreliable or need specific conditions.",
    "unproven": "No public exploit is known today. That can change, so still fix it in due course.",
}

# A short "what do I do with this?" for each check category.
CATEGORY_HELP: dict[str, str] = {
    "package": "Installed software with a known vulnerability. The fix is almost always to update the "
    "package - Sightline gives you the exact upgrade command in the patch plan.",
    "network": "Something reachable over the network is exposed or misconfigured. The fix is usually to "
    "add authentication, restrict who can connect (firewall), or turn encryption on.",
    "config": "A system setting that weakens security. The fix is a configuration change, described in the "
    "finding's remediation text.",
}

# First-run orientation, shown at the top of the help panel.
GETTING_STARTED = [
    "Start with the 'Fix now' list - those are the issues that are both serious and reachable.",
    "Use the patch plan: it is one copy-paste command per machine that clears every fixable package issue.",
    "Anything tagged KEV or 'Exploited in the wild' should jump the queue - criminals are using it today.",
    "Re-run the scan after fixing. Sightline shows you what is newly fixed and what is new since last time.",
    "A credentialed scan (--local or --ssh) is far more accurate than a network-only scan - prefer it.",
]


def explain(term: str) -> str | None:
    """Look up a glossary term or a priority/maturity keyword (case-insensitive)."""
    key = term.strip().lower()
    for source in (GLOSSARY, PRIORITY_HELP, MATURITY_HELP, CATEGORY_HELP):
        for name, text in source.items():
            if name.lower() == key:
                return text
    # allow partial matches for convenience
    for name, text in GLOSSARY.items():
        if key in name.lower():
            return f"{name}: {text}"
    return None


def help_payload() -> dict:
    """Everything the report/dashboard needs to render the help section."""
    return {
        "glossary": GLOSSARY,
        "priority": PRIORITY_HELP,
        "maturity": MATURITY_HELP,
        "category": CATEGORY_HELP,
        "getting_started": GETTING_STARTED,
    }
