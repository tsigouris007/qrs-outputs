### Priority Areas

Focus your security analysis on cookie parsing and validation:

#### 1. Input Validation Vulnerabilities
- **CWE-20**: Improper Input Validation
- Search for cookie parsing and extraction logic
- Identify validation checks on cookie names
- Look for handling of edge cases in cookie format

#### 2. Cookie Parsing Implementation
- Functions that parse `Set-Cookie` headers or cookie strings
- Regex patterns used for cookie name/value extraction
- Cookie name validation logic
- Edge case handling (empty names, special characters)

#### 3. Key Code Patterns to Search For
- Cookie header parsing functions (e.g., `parse_cookie`, cookie parsing methods)
- Regex patterns matching cookie key patterns
- Cookie name validation or filtering
- Logic that processes cookies starting with special characters
- Cookie dictionary/map construction variables
- Regex variables
- Internal methods

**You MUST use ALL iterations available to you**

#### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find regex patterns
 * @description Extracts the actual regex pattern strings from re module calls
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-regex-patterns
 * @tags regex
 *       security
 *       validation
 */

import python

predicate isRegexMethod(string name) {
  name in [
    "compile",
    "match",
    "search",
    "findall",
    "finditer",
    "sub",
    "subn",
    "split",
    "fullmatch"
  ]
}

from Call c, StrConst pattern, string methodName
where
  c.getFunc().(Attribute).getName() = methodName
  and c.getFunc().(Attribute).getObject().(Name).getId() = "re"
  and isRegexMethod(methodName)
  and pattern = c.getArg(0)
select c, "Regex pattern: " + pattern.getText() + " (method: " + methodName + ")"
```
