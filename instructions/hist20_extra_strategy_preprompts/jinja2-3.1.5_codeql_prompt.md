### Priority Areas

Focus your security analysis on the following high-priority vulnerability classes relevant to template engines:

#### 1. Sandbox Escape Vulnerabilities
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-184**: Incomplete List of Disallowed Inputs
- Look for patterns where template evaluation bypasses security restrictions

#### 2. Template Injection Patterns
- Examine filter implementations and their access to Python objects
- Investigate how templates can access object attributes and methods
- Check for ways to reach dangerous Python built-ins through attribute access

#### 3. Execution Context Escapes
- Functions that allow indirect code execution through template syntax
- Object attribute access that may expose sensitive methods
- Filter chains that could bypass sandbox restrictions

### Points of interest
- Sandbox files `*sandbox*` (wildcard match)
- Filtering files `*filter*` (wildcard match)
- Custom attribute functions or filters `*attr*` (wildcard match)
- Attribute methods or variables `attr`, `setattr`, `getattr`

## IMPORTANT

Pinpoint proper code flows and relevant snippets.
**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find sandbox or filter files
 * @description Finds all files with names containing 'sandbox' or 'filter'
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-sandbox-filter-files
 * @tags files
 *       sandbox
 *       filter
 *       security
 */

import python

from File f
where
  f.getBaseName().toLowerCase().matches("%sandbox%")
  or f.getBaseName().toLowerCase().matches("%filter%")
select f, "File matching sandbox/filter pattern: " + f.getBaseName()
```

```ql
/**
 * @name Find attr methods
 * @description Finds all methods and functions containing 'attr' in their name
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-attr-methods
 * @tags methods
 *       attributes
 *       security
 */

import python

from Function f
where f.getName().toLowerCase().matches("%attr%")
select f, "Method containing 'attr' found: " + f.getName()
```
