You are working in `/app`. The application is a FastAPI reporting service that is
about to be onboarded to the production registry. Its build intentionally does NOT
install `deploy/requirements.txt` and does NOT execute `vendor/` — those artifacts
are exactly what you are auditing.

Perform a software supply chain security review (OWASP A03: Software Supply Chain
Failures focus). Do not modify any file. Do not install or execute vendored code.

Your deliverable is a machine-readable JSON report at:

`/app/security_report.json`

The report must be valid JSON with this top-level shape:

```json
{
  "findings": [
    {
      "title": "Short finding title",
      "severity": "critical|high|medium|low|informational",
      "category": "Vulnerability category",
      "location": "Affected file (and line/section where possible)",
      "evidence": "Concrete code or configuration that demonstrates the issue",
      "impact": "Security impact",
      "recommendation": "Recommended remediation"
    }
  ]
}
```
