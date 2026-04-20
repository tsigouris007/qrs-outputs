### Priority Areas

Focus your security analysis on the following high-priority vulnerability classes relevant to YAML parsing libraries:

#### 1. Code Execution Vulnerabilities
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-502**: Deserialization of Untrusted Data
- Look for patterns where code or objects can be instantiated from serialized/parsed data

#### 2. Unsafe Deserialization Patterns
- **CWE-20**: Improper Input Validation
- Examine how the library handles YAML tags and type annotations
- Investigate object construction, module imports, and dynamic code execution during parsing

#### 3. Dynamic Code Execution
- Functions that evaluate, execute, or import code dynamically (`eval`, `exec`, `__import__`, `compile`)
- Object instantiation from strings or parsed structures
- Python-specific YAML tags that enable object creation

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find dangerous code execution methods
 * @description Finds all calls to eval, exec, compile, and __import__ functions
 * @kind problem
 * @problem.severity warning
 * @id py/find-dangerous-code-execution
 * @tags security
 *       injection
 *       code-execution
 */

import python

predicate isDangerousFunction(string name) {
  name in [
    "eval",
    "exec",
    "compile",
    "__import__"
  ]
}

from Call c, string funcName
where
  (
    c.getFunc().(Name).getId() = funcName
    and isDangerousFunction(funcName)
  )
  or
  (
    c.getFunc().(Attribute).getName() = funcName
    and isDangerousFunction(funcName)
  )
select c, "Dangerous code execution function found: " + funcName
```
