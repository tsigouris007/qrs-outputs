### Priority Areas

Focus your security analysis on credential protection during redirects:

#### 1. Any Authorization Header Handling
- **CWE-200**: Exposure of Sensitive Information
- Identify where headers are added to requests
- Look for redirect logic processing credentials

#### 2. Vulnerable Pattern: Missing Scheme/Protocol Checks
Search for handling logic that:
1. Rebuilds or reconstructs during redirects
2. Compares URLs or schemes during redirect processing
3. May NOT validate HTTP vs HTTPS context

#### 3. Key Areas to Inspect
- Methods handling authentication
- Functions reconstructing headers during redirects
- URL scheme comparisons in redirect paths
- Functions that contain `rebuild`, `reconstruct`, `proxy`/`proxies`, `resolve`, `auth` and other similar verbs

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find security-relevant verb functions
 * @description Finds all functions containing rebuild, reconstruct, proxy, resolve, auth and similar verbs
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-security-relevant-verbs
 * @tags security
 *       functions
 *       verbs
 */

import python

predicate isSecurityRelevantVerb(string name) {
  name.toLowerCase().matches("%rebuild%")
  or name.toLowerCase().matches("%reconstruct%")
  or name.toLowerCase().matches("%proxy%")
  or name.toLowerCase().matches("%proxies%")
  or name.toLowerCase().matches("%resolve%")
  or name.toLowerCase().matches("%auth%")
}

from Function f
where isSecurityRelevantVerb(f.getName())
select f, "Security-relevant function found: " + f.getName()
```

```ql
/**
 * @name Find hardcoded Authorization strings
 * @description Finds all hardcoded strings containing 'Authorization'
 * @kind problem
 * @problem.severity warning
 * @id py/find-hardcoded-authorization
 * @tags security
 *       hardcoded
 *       authorization
 *       credentials
 */

import python

from StrConst s
where s.getText().matches("%Authorization%")
select s, "Hardcoded Authorization string found: " + s.getText()
```
