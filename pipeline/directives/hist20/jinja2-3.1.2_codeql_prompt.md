## Objective
Search the codebase for the attribute injections on user input during filtering, that generates XML/HTML attributes, with specific focus on identifying:
1. How attribute keys are validated before being output
2. Whether keys containing special characters are rejected or allowed
3. How key-value pairs are processed and rendered into HTML attributes

## Search Strategy

### Step 1: Locate xmlattr Filter Implementation
Find the filter function that renders XML/HTML attributes:
- Look for filtering related files
- Look for filtering related methods
- Look for attribute filtering related methods
- Look for filter registration or filter functions in template filter modules
- Find where dictionary items are converted to HTML attribute strings
- Identify the function that builds attribute key-value pairs

### Step 2: Identify Key Validation Logic
Search for validation applied to attribute keys:
- Look for validation checks on dictionary keys before rendering
- Search for regex patterns or character checks on keys
- Find any validation that rejects certain characters (spaces, special chars)
- Check if validation is applied or if keys are used directly

### Step 3: Trace Key-to-Attribute Conversion
Follow the flow from dictionary keys to HTML output:
- How are keys extracted from input dictionary
- How are they prepared before rendering
- Whether validation happens before or during rendering
- How the final attribute string is constructed

## Key Code Patterns to Search For
- Filter function definitions: `*xmlattr*`
- Dictionary iteration patterns: `items`, `for` loops, etc.
- Key validation or rejection patterns
- Regex patterns checking for invalid characters
- Output formatting: `f-strings`, `format()`, `%` formatting for attributes
- Validation calls: `raise ValueError`, `if key in ...`

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find xmlattr methods
 * @description Finds all methods and functions named 'xmlattr' or containing 'xmlattr' in their name
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-xmlattr-methods
 * @tags methods
 *       xml
 *       security
 */

import python

from Function f
where f.getName().toLowerCase().matches("%xmlattr%")
select f, "Method containing 'xmlattr' found: " + f.getName()
```

```ql
/**
 * @name Find xmlattr in template strings
 * @description Finds string literals containing xmlattr filter which may indicate Jinja2 template XSS risk
 * @kind problem
 * @problem.severity warning
 * @id py/find-xmlattr-template-strings
 * @tags security
 *       xss
 *       jinja2
 *       xml
 */

import python

from StrConst s, string content
where
  content = s.getText()
  and
  (
    content.matches("%|xmlattr%")
    or content.matches("%xmlattr(%")
    or content.regexpMatch(".*\\{\\{.*xmlattr.*\\}\\}.*")
    or content.regexpMatch(".*\\{%.*xmlattr.*%\\}.*")
  )
select s, "Template string containing xmlattr filter: potential XSS vector"
```
