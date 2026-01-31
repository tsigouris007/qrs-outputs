### Priority Areas

Focus your security analysis on identifying missing length validation in validation functions:

#### 1. Regular Expression Denial of Service (ReDoS) in Email Validation
- **CWE-1333**: Inefficient Regular Expression Complexity
- Identify email validation functions that process user input
- Look for regex patterns applied to unvalidated string lengths

#### 2. Vulnerable Pattern
Search for functions that:
1. Accept email address strings from user input
2. Apply regex validation directly to the string
3. **LACK length bounds checks** before regex processing
4. Process potentially very long email strings
5. Look for functions that perform regex checks including `regex` in their names.
6. Look for static regex strings.
7. Look for functions that validate fiedls including `validate` in their names.

#### 3. Key Functions to Inspect
- Email validation functions in network/email modules
- Functions accepting email strings with regex patterns
- Validation occurring on untrusted user input
- Regex fullmatch/search operations on email fields

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find regex operations
 * @description Finds all regular expression operations including compile, match, search, findall, sub, etc.
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-regex-operations
 * @tags regex
 *       validation
 *       security
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

from Call c, string methodName
where
  c.getFunc().(Attribute).getName() = methodName
  and c.getFunc().(Attribute).getObject().(Name).getId() = "re"
  and isRegexMethod(methodName)
select c, "Regex operation found: re." + methodName + "()"
```
