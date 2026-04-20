### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for HTTP request smuggling in this async HTTP library, focus on RFC compliance violations. CVE-2023-47627 involves multiple explicit violations of RFC 9110 and RFC 9112 specifications in the Python HTTP parser.

#### HTTP Request Smuggling via RFC Violations
- **CWE-444**: Inconsistent Interpretation of HTTP Requests (due to non-compliant parsing)
- **CWE-436**: Interpretation Conflict (parser accepts what spec forbids)

### Key Validation Criteria

#### 1. RFC 9110 Section 8.6 - Content-Length Validation
Validate findings about Content-Length parsing:
- **Does the code parse without prior validation?** Look for direct `int()` on header values
- **Does it accept prefixes?** Should reject `+256`, `-0` but accept only ASCII digits
- **Does it accept underscores?** Should reject `0_2e` format
- **Is validation happening?** Should require `.isdigit()` check before `int()`

#### 2. RFC 9110 Section 5.5 - Forbidden Characters in Header Values
Validate findings about header value character validation:
- **Are CR/LF/NUL forbidden?** RFC explicitly forbids `\x0d`, `\x0a`, `\x00` in header values
- **Does the code check?** Look for missing character validation loops
- **Is replacement happening?** RFC allows replacing with space, but code should reject or sanitize
- **Are they bypassing validation?** Find where these characters are processed without checking

#### 3. RFC 9112 Section 5.1 - Header Field Format
Validate findings about header name/colon parsing:
- **Is whitespace before colon rejected?** RFC forbids ANY whitespace between name and colon
- **Is stripping happening?** Look for `.strip()` or `.lstrip()` on header names
- **Example: `Name : value`** Should be rejected, but code might strip the space
- **Is this explicit RFC violation?** The code removes whitespace that should cause rejection

#### 4. True Positive Indicators
- **Direct RFC violation** - code does the opposite of what RFC requires
- **Missing validation** - should check but doesn't (e.g., Content-Length parsing)
- **Overly lenient** - accepts what spec explicitly forbids (e.g., whitespace before colon)
- **Character filtering missing** - doesn't check for NUL/CR/LF in headers
- **Enablement of smuggling** - these violations enable parsing differences with proxies

#### 5. False Positive Indicators
- Finding describes something spec-compliant (if code follows RFC, it's not vulnerable)
- Issue is about implementation details rather than RFC violations
- Code correctly rejects invalid input
- Finding misidentifies where validation occurs

### Critical Focus Areas

Look for:
- **Content-Length parsing without prior validation** - using integer directly without validating
- **Missing forbidden character checks** - NUL (`\x00`), CR (`\r`), LF (`\n`) in headers not validated
- **Whitespace stripping before colon** - header names having stripped before colon
- **Explicit RFC violation patterns** - code doing opposite of what RFC requires
- **Non-validation acceptance** - headers bypassing required RFC checks

Reject findings that describe spec-compliant behavior. Accept findings showing actual violation of RFC 9110 or RFC 9112 requirements that create parsing inconsistencies with RFC-compliant proxies.

**You MUST use ALL iterations available to you**
