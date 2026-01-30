### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for cookie parsing in this WSGI library:

#### Cookie Injection via Improper Validation
- **CWE-20**: Improper Input Validation
- **Root cause**: Cookies with empty or missing keys are parsed incorrectly
- **Potential Issues**: Malformed cookie names can shadow legitimate cookies

### Key Validation Criteria

#### 1. Exploitability Assessment
- **What cookie names are accepted?** Does parser accept cookies starting with special characters?
- **Can attacker control cookie names?** Can adjacent subdomains set malicious cookies?
- **Real scenario**: Cookie with format regex be bypassed?
- **Impact**: Can attacker's cookie shadow or override legitimate application cookies?

#### 2. True Positive Indicators
- Cookie parsing accepts cookies with empty or missing key names
- Regex pattern or parsing logic allows bypassing via special delimiters such as `=`, `_`, `-` or similar
- Regex pattern or parsing logic allows nameless cookies without a key=value format
- **No validation** that cookie key is non-empty before use
- Cookies are added to result dictionary without checking for valid key names
- Parsing logic extracts key/value but doesn't validate key is present/non-empty
- Code path accepts cookie entries that bypass regex checkers and processes them

#### 3. False Positive Indicators
- Cookie name validation explicitly checks that key is non-empty
- Empty keys are discarded/skipped before adding to result
- Regex requires at least one character in key name
- Cookies with invalid names are filtered out in same code path
- Logic explicitly rejects or skips cookies without valid key names

### Critical Focus Areas

- Cookie header parsing and extraction
- Cookie name validation and filtering logic
- Regex patterns for cookie key matching
- Cookie dictionary/map population from parsed values

**You MUST use ALL iterations available to you**
