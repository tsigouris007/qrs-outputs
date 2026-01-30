### Code Patterns to Search For

#### 1. Async Request Handlers
- Look for **async functions** or **async methods** that accept `Request` objects as parameters
- Search for patterns: `async def`, method definitions with `Request` parameter

#### 2. Request Body Access
- Identify calls to **`await request.json()`** in async methods
- Identify calls to **`request.body()`** followed by `json.loads()`
- Identify calls to **`await request.stream()`** or **`await request.receive()`** that process JSON
- Look for patterns where request body is being read/parsed

#### 3. Header Access Patterns
- Look for code that reads `request.headers` or `request.get("content-type")`
- Identify if header reading occurs **AFTER** body parsing (late validation)
- Search for patterns where Content-Type header is accessed but on a separate code path

#### 4. State-Changing Operations
- Look for endpoints handling POST, PUT, PATCH, DELETE methods
- Identify if these endpoints use **cookie-based authentication** (e.g., checking cookies, sessions, tokens passed via headers from cookies)
- Search for patterns with `request.cookies`, `request.session`, `Authorization` header reads

### Specific Code Constructs to Flag

- **Async methods with Request parameter** that call `await request.json()`
- **Request body parsing** (`json.loads()`, `.json()`) **without prior Content-Type header inspection**
- **Path operations** marked with POST/PUT/PATCH decorators that read JSON bodies
- **Direct body parsing** before any conditional header checks
- Functions with control flow where body is parsed in the **main path** rather than inside a conditional Content-Type check

### Important

- Except file names containing the `tutorial` from queries
- Focus on `routing` ones

**You MUST use ALL iterations available to you**

#### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find async functions
 * @description Finds all async def function definitions
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-async-functions
 * @tags functions
 *       async
 */

import python

from Function f
where f.isAsync()
select f, "Async function found: " + f.getName()
```

```ql
/**
 * @name Find await request.body() assignments
 * @description Finds all assignments where a variable is assigned the result of await request.body()
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-request-body-await
 * @tags async
 *       request
 *       security
 */

import python

from AssignStmt a, Await aw, Call c
where
  a.getValue() = aw
  and aw.getValue() = c
  and c.getFunc().(Attribute).getName() = "body"
  and c.getFunc().(Attribute).getObject().(Name).getId() = "request"
select a, "Found 'await request.body()' assignment"
```
