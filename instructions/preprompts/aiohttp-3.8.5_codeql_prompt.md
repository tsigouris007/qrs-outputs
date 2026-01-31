### Priority Areas

Focus CodeQL analysis on HTTP header parsing and validation for RFC compliance violations. The Python HTTP parser has multiple specific RFC violations that enable request smuggling attacks.

**Relevant CWEs:**
- CWE-444: Inconsistent Interpretation of HTTP Requests
- CWE-436: Interpretation Conflict

### Analysis Strategy

#### 1. Content-Length Header Parsing - RFC 9110 Section 8.6
Examine how Content-Length values are parsed and validated:
- Search for use of `int()` constructor on header values without prior validation
- Look for Content-Length parsing that accepts `+` prefix (e.g., `+256`)
- Identify parsing that accepts `-` prefix (e.g., `-0`)
- Find parsing that accepts underscores (e.g., `0_2e`)
- Verify that ONLY ASCII digits are accepted per RFC 9110 specification
- Find where validation should use `.isdigit()` or similar character-by-character checking

#### 2. Header Value Forbidden Characters - RFC 9110 Section 5.5
Analyze what characters are validated in header values:
- Look for missing validation of NUL bytes (`\x00`) in header values
- Search for missing validation of CR (`\r`, `\x0d`) characters
- Find missing validation of LF (`\n`, `\x0a`) characters
- Identify header value processing that accepts these forbidden characters
- Check for headers that preserve CR/LF without replacing with space
- Find patterns where forbidden characters bypass processing

#### 3. Header Field Format - RFC 9112 Section 5.1
Investigate header field name validation:
- Look for stripping of whitespace BEFORE the colon in header names
- Search for `.strip()` or `.lstrip()` calls on header names
- Find cases where whitespace before colon (e.g., `Name : value`) is tolerated
- Verify that ANY whitespace before colon should cause rejection
- Identify header field parsing that removes spaces/tabs from field names
- Check for overly lenient header field format parsing

#### 4. Request Smuggling Attack Vectors
Understand where parsing differences create vulnerabilities:
- Identify where lenient parsing creates proxy/backend interpretation mismatch
- Find parsing that accepts input that RFC-compliant proxies would reject
- Examine where invalid headers could confuse body/header boundary detection
- Check for cases where invalid Content-Length leads to body length confusion
- Locate where forbidden characters in headers bypass security checks

### Critical Focus Areas

Write CodeQL queries that identify:
- **Direct int() usage** on Content-Length or other numeric headers without prior `.isdigit()` validation
- **Character filtering missing** for NUL (`\x00`), CR (`\x0d`), LF (`\x0a`) in header values
- **Whitespace stripping before colon** in header name parsing (look for `.strip()`, `.lstrip()` on header names before colon extraction)
- **RFC-specific violation patterns** where implementation explicitly violates RFC 9110/9112
- **Non-validation acceptance** where invalid but interpretable headers are processed without rejection

The vulnerabilities are RFC specification violations - objective failures to enforce RFC 9110 and RFC 9112 requirements in header parsing.

## IMPORTANT

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find int, isdigit, strip methods
 * @description Finds all calls to int(), isdigit(), and strip() methods
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-int-isdigit-strip
 * @tags methods
 *       validation
 *       sanitization
 */

import python

predicate isTargetMethod(string name) {
  name = "int"
  or name = "isdigit"
  or name.matches("%strip%")
}

from Call c, string funcName
where
  (
    c.getFunc().(Name).getId() = funcName
    and isTargetMethod(funcName)
  )
  or
  (
    c.getFunc().(Attribute).getName() = funcName
    and isTargetMethod(funcName)
  )
select c, "Method found: " + funcName
```
