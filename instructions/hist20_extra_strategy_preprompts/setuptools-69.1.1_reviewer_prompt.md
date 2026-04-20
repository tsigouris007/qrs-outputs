### Review Priority

When reviewing CodeQL findings for command injection in download functions:

- **CWE-94**: Improper Control of Code Generation
- **Root cause**: URLs directly used in shell command construction
- **Attack**: Malicious package URL with shell metacharacters → arbitrary command execution

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker control URLs?** Package URLs from untrusted servers or user input?
- **What can be executed?** Do shell metacharacters lead to arbitrary code execution?
- **Download context**: Does it affect downloading operations?
- **Real scenario**: Installations from maliciously crafted URLs?

#### 2. True Positive Indicators
- URLs used in shell command strings (string formatting/concatenation)
- Commands executed via `os.system()` or `shell=True` subprocess
- Missing quoting/escaping of URL components
- Download functions with URL parameters

#### 3. False Positive Indicators
- `subprocess.run()` with list of arguments (not shell string)
- URLs properly quoted/escaped before shell execution
- Direct subprocess calls without shell interpretation
- Proper separation of command and URL arguments

### Critical Points

- URL handling before command execution
- Look for: `os.system()`, `shell=True`, or string-based command construction with URLs

**You MUST use ALL iterations available to you**
