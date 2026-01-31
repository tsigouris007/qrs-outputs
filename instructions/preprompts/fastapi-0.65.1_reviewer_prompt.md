### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for this web framework, prioritize validation of:

#### Cross-Site Request Forgery
- **CWE-352**: Cross-Site Request Forgery (CSRF)
- **CWE-346**: Origin Validation Error

### Validation of Findings

#### 1. Verify Request Handler Context
- **Is this a state-changing endpoint?** Check if method is POST, PUT, PATCH, or DELETE
- **Is authentication cookie-based?** Look for cookie usage, session checks, or authentication headers
- **Does it parse JSON?** Confirm `await request.json()` or `json.loads()` is called

#### 2. Trace Header Validation Order
- **When is Content-Type accessed?** Is it BEFORE or AFTER body parsing?
- **Is there a Content-Type check?** Search for `request.headers.get("content-type")` or similar patterns
- **What happens in the check?** Does it validate against `application/json` or compatible types?
- **Where is the parse call?** If Content-Type check exists, is JSON parsing inside that conditional or in the main code path?

#### 3. Analyze Control Flow
- **Early exit on bad Content-Type?** Look for rejection/exception when Content-Type is not JSON-compatible
- **Implicit acceptance?** If there's no explicit Content-Type validation, body parsing is unconditional
- **Conditional parsing?** Code that only parses JSON IF Content-Type is `application/json` is protected
- **Main path parsing?** Code that parses JSON regardless of Content-Type is vulnerable

#### 4. True Positive Indicators
- Endpoint handles state-changing method (POST/PUT/PATCH/DELETE)
- Uses cookie-based authentication
- Calls `await request.json()` or parses body as JSON
- **No Content-Type header check before parsing**, OR
- **Content-Type check exists but parsing happens unconditionally in main code path** (check is in else branch or separate function)
- Simple CORS requests with `text/plain` could reach the JSON parsing code

#### 5. False Positive Indicators
- Content-Type is validated BEFORE body parsing in same code path
- JSON parsing only occurs inside a conditional block checking Content-Type is `application/json` or compatible
- Endpoints use stateless authentication (JWT tokens, API keys, not cookies)
- Endpoints only handle GET/HEAD/OPTIONS requests
- CSRF tokens or SameSite cookies provide additional protection

**You MUST use ALL iterations available to you**
