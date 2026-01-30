### Priority Areas

Focus your security analysis on credential protection during HTTP redirects:

#### 1. Authorization Header Handling During Redirects
- **CWE-522**: Insufficiently Protected Credentials
- Identify where auth headers are preserved/modified during redirects
- Look for redirect handling logic that processes authentication

#### 2. Vulnerable Pattern: Scheme/Protocol Changes
Search for redirect logic that:
1. Processes HTTP(S) redirects
2. Handles Authorization headers
3. Compares URLs or origins to decide header retention
4. May NOT validate security context changes (HTTPS → HTTP)
5. Functions that contain `redirect` or `auth` are critical targets

#### 3. Key Areas to Inspect
- Methods handling redirect responses
- Functions manipulating Authorization headers during redirects
- URL/origin comparison logic
- Session-level redirect processing

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find redirect or auth function definitions and calls
 * @description Finds all definitions and calls to functions containing 'redirect' or 'auth'
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-redirect-auth-definitions-calls
 * @tags security
 *       redirect
 *       auth
 *       authentication
 */

import python

predicate isRedirectRelated(string name) {
  name.toLowerCase().matches("%redirect%")
}

predicate isAuthRelated(string name) {
  name.toLowerCase().matches("%auth%")
}

from AstNode node, string name, string category, string usageType
where
  (
    // Function definitions
    (
      node.(Function).getName() = name
      and isRedirectRelated(name)
      and category = "redirect"
      and usageType = "definition"
    )
    or
    (
      node.(Function).getName() = name
      and isAuthRelated(name)
      and category = "auth"
      and usageType = "definition"
    )
    or
    // Direct calls
    (
      node.(Call).getFunc().(Name).getId() = name
      and isRedirectRelated(name)
      and category = "redirect"
      and usageType = "direct call"
    )
    or
    (
      node.(Call).getFunc().(Name).getId() = name
      and isAuthRelated(name)
      and category = "auth"
      and usageType = "direct call"
    )
    or
    // Method calls
    (
      node.(Call).getFunc().(Attribute).getName() = name
      and isRedirectRelated(name)
      and category = "redirect"
      and usageType = "method call"
    )
    or
    (
      node.(Call).getFunc().(Attribute).getName() = name
      and isAuthRelated(name)
      and category = "auth"
      and usageType = "method call"
    )
  )
select node, "[" + category + "] " + usageType + ": " + name
```

```ql
/**
 * @name Find redirect or auth functions
 * @description Finds all functions containing 'redirect' or 'auth' in their name
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-redirect-auth-functions
 * @tags security
 *       redirect
 *       auth
 *       authentication
 */

import python

from Function f
where
  f.getName().toLowerCase().matches("%redirect%")
  or f.getName().toLowerCase().matches("%auth%")
select f, "Function found: " + f.getName()
```
