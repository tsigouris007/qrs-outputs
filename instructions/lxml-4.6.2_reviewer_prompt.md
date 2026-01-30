### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

Concentrate on HTML sanitization implementation with emphasis on attribute filtering completeness. The vulnerability class involves cross-site scripting through inadequate attribute validation in HTML cleaning operations.

**Relevant CWEs:**
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-116: Improper Encoding or Escaping of Output
- CWE-20: Improper Input Validation

### Key Validation Criteria

#### 1. Attribute Filtering Completeness
Verify that HTML attribute sanitization covers all dangerous vectors:
- **MISSING attributes**: Check if `formaction` attribute is absent from link/URL attribute lists
- **Completeness**: Do attribute lists include both older (action, href) and HTML5 (formaction) variants?
- **Consistency**: If `action` is in URL validation list, is `formaction` also there?
- **Form submission vectors**: Coverage of all attributes that can trigger navigation or script execution
- **Attribute override behavior**: `formaction` on buttons/inputs overrides form's `action` - is it sanitized?

#### 2. URL Scheme Validation
Examine validation of URLs within HTML attributes:
- Detection of JavaScript and data URLs
- Handling of protocol-relative URLs
- Case-insensitive scheme matching
- Coverage of all URL-accepting attributes

#### 3. Parser Consistency
Assess consistency between HTML parsing and attribute filtering:
- Agreement on attribute boundaries and names
- Handling of duplicate or conflicting attributes
- Processing of namespaced attributes
- Edge case handling in malformed HTML

#### 4. Defense Depth
Evaluate layered security in the HTML cleaning process:
- Multiple sanitization passes and their effectiveness
- Fallback behaviors when parsing fails
- Safe defaults for unrecognized attributes
- Error handling that doesn't bypass security

### Critical Focus Areas

Validate that findings demonstrate actual XSS risks through **incomplete attribute lists**, particularly:
- **Missing `formaction`**: Attribute lists for URL validation that include `action`, `href`, `src` but NOT `formaction`
- **HTML5 gaps**: Sanitization logic written for HTML4 that doesn't cover HTML5 form attributes
- **Bypass via newer attributes**: Using HTML5 `formaction` to bypass sanitization of older `action` attribute
- **Configuration dependency**: Vulnerability manifests when `safe_attrs_only=False` and `forms=False` (non-default but valid configuration)

Assess whether findings show `formaction` attribute missing from URL/link attribute definitions, allowing `javascript:` URLs to bypass sanitization.

**You MUST use ALL iterations available to you**
