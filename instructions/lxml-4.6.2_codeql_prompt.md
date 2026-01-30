### Priority Areas

Focus CodeQL analysis on HTML sanitization and attribute filtering mechanisms. The primary concern involves cross-site scripting vulnerabilities in HTML cleaning functionality where certain attributes may bypass sanitization filters.

**Relevant CWEs:**
- CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
- CWE-116: Improper Encoding or Escaping of Output
- CWE-20: Improper Input Validation

### Analysis Strategy

#### 1. HTML Attribute Lists and Definitions
Look for where HTML attributes are defined for sanitization purposes:
- **Target**: Lists of link-related attributes (href, src, action, etc.) used for URL validation
- **Missing pattern**: `formaction` attribute NOT present in link attribute lists
- **Key files**: HTML cleaner module, attribute definition files (defs.py, clean.py)
- **Vulnerable pattern**: Attribute lists for URL-containing attributes that include `action`, `href`, `src` but DON'T include `formaction`

#### 2. Form Element Security
Investigate security controls around form-related HTML elements:
- Form submission attributes: `action` vs `formaction`
- HTML5 form attributes on buttons and inputs
- **Specific issue**: `formaction` overrides form's `action` attribute but may not be sanitized like `action` is
- Look for attribute validation that handles `action` but not `formaction`

#### 3. HTML Parser Integration and Attribute Completeness
Analyze attribute list definitions in HTML cleaning code:
- **Look for**: Lists/sets of attributes that accept URLs (link_attrs, url_attrs, etc.)
- **Check completeness**: Does the list include all HTML attributes that can contain URLs?
- **HTML5 attributes**: Newer form-related attributes like `formaction`, `formmethod`, `formenctype`
- **Missing validation**: Attributes that can execute JavaScript via `javascript:` URLs but aren't in URL validation lists

#### 4. Sanitization Bypass via Missing Attributes
Search for bypass mechanisms due to incomplete attribute coverage:
- Attributes that can contain JavaScript URLs but aren't sanitized
- HTML5 form attributes (`formaction`, `formmethod`, `formtarget`) that may bypass older sanitization logic
- Attributes that override others (e.g., `formaction` overrides `action`) but aren't in validation lists
- Compare form-related attributes: if `action` is validated, is `formaction` also validated?

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find clean or html_clean methods
 * @description Finds all methods containing 'clean' or 'html_clean' in their name
 * @kind problem
 * @problem.severity warning
 * @id py/find-clean-methods
 * @tags security
 *       xss
 *       sanitization
 *       lxml
 */

import python

predicate isCleanMethod(string name) {
  name.toLowerCase().matches("%clean%")
  or name.toLowerCase().matches("%html_clean%")
  or name.toLowerCase().matches("%sanitize%")
  or name.toLowerCase().matches("%purify%")
}

from AstNode node, string name, string usageType
where
  (
    // Function definitions
    node.(Function).getName() = name
    and isCleanMethod(name)
    and usageType = "function definition"
  )
  or
  (
    // Direct calls
    node.(Call).getFunc().(Name).getId() = name
    and isCleanMethod(name)
    and usageType = "direct call"
  )
  or
  (
    // Method calls
    node.(Call).getFunc().(Attribute).getName() = name
    and isCleanMethod(name)
    and usageType = "method call"
  )
select node, "[" + usageType + "] Clean method: " + name
```

```ql
/**
 * @name Find Cleaner imports
 * @description Finds all imports of Cleaner and related lxml/bleach sanitization classes
 * @kind problem
 * @problem.severity warning
 * @id py/find-cleaner-imports
 * @tags security
 *       xss
 *       sanitization
 *       lxml
 *       imports
 */

import python

predicate isCleanerImport(string name) {
  name = "Cleaner"
  or name = "clean"
  or name = "clean_html"
  or name = "lxml"
  or name = "bleach"
  or name = "sanitizer"
  or name = "HTMLParser"
}

predicate isCleanerModule(string name) {
  name.matches("%lxml%")
  or name.matches("%lxml.html%")
  or name.matches("%lxml.html.clean%")
  or name.matches("%bleach%")
  or name.matches("%html.parser%")
  or name.matches("%html_sanitizer%")
}

from AstNode node, string importName, string importType, string location
where
  location = node.getLocation().getFile().getRelativePath()
  and
  (
    // from lxml.html.clean import Cleaner
    (
      node.(ImportMember).getName() = importName
      and isCleanerImport(importName)
      and importType = "from import"
    )
    or
    // import lxml.html.clean
    (
      node.(Import).getAName().(Alias).getAsname().(Name).getId() = importName
      and isCleanerImport(importName)
      and importType = "import alias"
    )
    or
    // from lxml.html import clean, Cleaner
    (
      exists(ImportMember im |
        node = im
        and im.getName() = importName
        and isCleanerImport(importName)
      )
      and importType = "member import"
    )
  )
select node, "[" + importType + "] Import: " + importName + " in " + location
```

```ql
/**
 * @name Find arrays used by Cleaner objects
 * @description Finds arrays/lists being passed to Cleaner objects (potential XSS allowlist issues)
 * @kind problem
 * @problem.severity warning
 * @id py/find-cleaner-arrays
 * @tags security
 *       xss
 *       sanitization
 *       lxml
 *       allowlist
 */

import python

predicate isCleanerInstantiation(Call c) {
  c.getFunc().(Name).getId() = "Cleaner"
  or c.getFunc().(Attribute).getName() = "Cleaner"
}

predicate isCleanerConfigKeyword(string name) {
  name in [
    "allow_tags",
    "remove_tags",
    "kill_tags",
    "safe_attrs",
    "safe_attrs_only",
    "remove_unknown_tags",
    "host_whitelist",
    "whitelist_tags",
    "scripts",
    "javascript",
    "embedded",
    "frames",
    "forms",
    "annoying_tags",
    "links",
    "meta",
    "page_structure",
    "processing_instructions",
    "style",
    "inline_style",
    "add_nofollow"
  ]
}

from Call c, Keyword k, string paramName, string location
where
  location = c.getLocation().getFile().getRelativePath()
  and isCleanerInstantiation(c)
  and k = c.getAKeyword()
  and paramName = k.getArg()
  and
  (
    // List/array arguments
    k.getValue() instanceof List
    or
    // Set arguments
    k.getValue() instanceof Set
    or
    // Tuple arguments
    k.getValue() instanceof Tuple
    or
    // Variable that might be a list
    k.getValue() instanceof Name
  )
select c, "Cleaner with array parameter '" + paramName + "' in " + location
```
