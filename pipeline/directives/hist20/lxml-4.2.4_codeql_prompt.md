## Objective
Search the codebase for HTML cleaner implementations that filter dangerous URLs, with specific focus on identifying:
1. How URL schemes are validated or detected in href attributes
2. Whether URL decoding/unescaping is performed before validation
3. JavaScript protocol URL filtering mechanisms

## Search Strategy

### Step 1: Locate HTML Cleaner URL Handling
Find code that processes and validates URLs in HTML attributes:
- Search for functions that handle URL scheme validation
- Find attribute filtering logic for `href` and event handler attributes
- Identify where URL validation occurs in HTML cleaning modules

### Step 2: Identify URL Scheme Detection
Search for code patterns related to JavaScript URL detection:
- Look for string matching or prefix checks for `javascript:` scheme
- Find conditional checks like `startswith()` or `startswith('javascript')`
- Search for scheme extraction or URL parsing patterns
- Look for `urlsplit()` or similar URL parsing function calls

### Step 3: Find URL Decoding Logic
Find whether URLs are decoded before validation:
- Search for URL decoding or unquoting functions (e.g., `unquote`, `unquote_plus`, `urllib.parse`)
- Check if URL decoding is performed BEFORE scheme validation
- Look for import statements related to URL parsing/decoding
- Identify the order of operations: decode first vs validate first

## Key Code Patterns to Search For
- URL scheme checking: `javascript:` detection patterns
- Look for `*javascript*` related methods
- Import statements for URL utilities: `urlparse`, `urllib.parse`, `unquote`
- Function calls for URL validation and decoding
- Conditional checks on URL properties or scheme
- Loop or iteration patterns processing multiple URLs/attributes
- String normalization or cleaning before validation

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find javascript named methods
 * @description Finds all methods and functions named 'javascript' or containing 'javascript' in their name
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-javascript-methods
 * @tags methods
 *       naming
 *       security
 */

import python

from Function f
where f.getName().toLowerCase().matches("%javascript%")
select f, "Method containing 'javascript' found: " + f.getName()
```

```ql
/**
 * @name Comprehensive javascript method detection
 * @description Finds all javascript-related methods including class methods, static methods, and decorated functions
 * @kind problem
 * @problem.severity recommendation
 * @id py/comprehensive-javascript-detection
 * @tags methods
 *       naming
 *       security
 *       xss
 */

import python

predicate isJavascriptRelated(string name) {
  name.toLowerCase().matches("%javascript%")
  or name.toLowerCase().matches("%js_%")
  or name.toLowerCase().matches("%_js%")
  or name.toLowerCase().matches("%exec_js%")
  or name.toLowerCase().matches("%eval_js%")
  or name.toLowerCase().matches("%run_js%")
  or name.toLowerCase().matches("%inject_js%")
}

from AstNode node, string name, string usageType, string location
where
  location = node.getLocation().getFile().getRelativePath()
  and
  (
    // Function/method definitions
    (
      node.(Function).getName() = name
      and isJavascriptRelated(name)
      and usageType = "function definition"
    )
    or
    // Direct calls
    (
      node.(Call).getFunc().(Name).getId() = name
      and isJavascriptRelated(name)
      and usageType = "direct call"
    )
    or
    // Method calls on objects
    (
      node.(Call).getFunc().(Attribute).getName() = name
      and isJavascriptRelated(name)
      and usageType = "method call"
    )
  )
select node, usageType + ": " + name + " in " + location
```
