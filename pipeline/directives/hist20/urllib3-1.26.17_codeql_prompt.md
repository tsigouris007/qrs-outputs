### Priority Areas

Focus your security analysis on request body handling during HTTP redirects:

#### 1. HTTP Status Code Handling in Redirects
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor
- Search for redirect logic that processes specific HTTP status codes
- Identify where request method changes occur (POST → GET conversions)
- Look for body stripping or preservation logic

#### 2. Request Method Transitions During Redirects
- Methods that handle status 301, 302, 303 redirect responses
- Code that changes request method based on status code
- Logic that preserves or clears request body during method changes
- Functions dealing with redirect location processing

#### 3. Key Code Patterns to Search For
- Status code conditionals (checking 301, 302, 303)
- Method reassignments (setting method to "GET" or similar)
- Body variable assignments during redirect handling
- Request preparation before re-submitting to redirect location
- Pool and handler files are interesting
- Methods that modify requests or redirect are also interesting

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find hardcoded 30x HTTP codes
 * @description Finds all hardcoded 30x HTTP redirect status codes
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-hardcoded-30x-codes
 * @tags security
 *       http
 *       redirect
 *       status-codes
 */

import python

from Num n
where
  n.getN() in [300, 301, 302, 303, 304, 305, 306, 307, 308]
select n, "Hardcoded 30x HTTP code found: " + n.getN().toString()
```

```ql
/**
 * @name Find hardcoded GET or POST verbs
 * @description Finds all hardcoded HTTP GET and POST method strings
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-hardcoded-http-verbs
 * @tags security
 *       http
 *       methods
 *       verbs
 */

import python

from StrConst s
where
  s.getText() = "GET"
  or s.getText() = "POST"
select s, "Hardcoded HTTP verb found: " + s.getText()
```
