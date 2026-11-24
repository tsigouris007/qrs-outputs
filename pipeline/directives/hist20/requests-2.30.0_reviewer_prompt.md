### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for credential exposure in redirects:

**Any Authorization headers sent to destination servers during HTTPS redirects**
- **CWE-200**: Exposure of Sensitive Information
- **Root cause**: Missing HTTPS scheme validation before adding headers
- **Attack**: HTTP redirect to HTTPS endpoint → Any Authorization headers leaked to destination

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker trigger redirects?** Malicious server sends redirect to HTTPS endpoint
- **What headers leak?** Any Authorization header credentials sent to destination server?
- **HTTPS context**: Does vulnerability specifically affect HTTPS redirects?
- **Real scenario**: Request → redirect to HTTPS → credentials exposed

#### 3. True Positive Indicators
- Any Authorization header added without scheme check
- Header added to HTTPS requests where it would be tunneled
- Missing validation of HTTP vs HTTPS context
- Credentials leaked to destination servers

#### 4. False Positive Indicators
- Scheme validated before reconstructing headers
- HTTPS redirects explicitly excluded addition
- Proper check in place
- Proxy headers only added to HTTP requests

### Critical Points

- rebuild/reconstruction/proxy/resolve methods handling headers
- Session or authorization files
- Any type of header assignment logic
- Redirects with credentials passing through Authorization or Proxy-Authorization headers
- Look for: absence of HTTPS scheme checks

**You MUST use ALL iterations available to you**
