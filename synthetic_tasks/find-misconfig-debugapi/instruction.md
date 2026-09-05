You are working in `/app`. The application is an internal FastAPI admin dashboard
that is being prepared for production deployment.

Perform a security configuration audit (OWASP A02: Security Misconfiguration
focus). Do not modify application code.

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
      "location": "Affected file, function, endpoint, or component",
      "evidence": "Concrete code or behavior that demonstrates the issue",
      "impact": "Security impact",
      "recommendation": "Recommended remediation"
    }
  ]
}
```

Cover every distinct misconfiguration you can substantiate from the code and
running service. Include enough detail for each finding to be actionable.
