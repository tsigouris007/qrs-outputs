### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for credential exposure in redirects:

**Authorization headers sent to HTTP after HTTPS redirects**
- **CWE-522**: Insufficiently Protected Credentials
- **Root cause**: Missing security context validation (scheme change)
- **Potential Issues**: HTTPS request with auth → redirect to plaintext HTTP

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker control redirect?** Malicious server sends redirect response
- **What headers leak?** Authorization header sent to unencrypted channel?
- **Same-host attack**: Does vulnerability occur on redirects to same hostname but different scheme?
- **Real scenario**: HTTPS endpoint redirects to HTTP on same domain

#### 2. True Positive Indicators
- Redirect handling preserves auth headers based only on hostname
- Missing check for scheme changes (HTTP ↔ HTTPS)
- Missing check for port changes
- Authorization header NOT stripped on downgrade

#### 4. False Positive Indicators
- Scheme/protocol validated before deciding to strip headers
- Headers stripped on any security context change
- Port and scheme both checked for equality
- Downgrade from HTTPS to HTTP explicitly prohibited

### Critical Focus Areas

- Sessions/redirect handling methods
- URL comparison logic during redirects
- Authorization header manipulation

**You MUST use ALL iterations available to you**
