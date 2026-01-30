### Priority Areas

Focus on arbitrary code execution vulnerabilities in image expression evaluation.

**Relevant CWEs:**
- CWE-94: Improper Control of Generation of Code
- CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code

### Analysis Strategy

**Suspicious Functions**: eval/exec/compile/import
**Primary Goal**: Find eval-based code execution patterns where user input flows to **Suspicious Functions** without proper sanitization.

#### 1. Dynamic Code Evaluation in ImageMath
Look for **Suspicious Functions** patterns used for expression evaluation:
- **Focus on**: **Suspicious Functions** in any module
- **Vulnerable pattern**: Expression strings or code passed to **Suspicious Functions** that originate from user input
- **Key pattern**: **Suspicious Functions** called on expressions constructed from untrusted data

#### 2. Expression Parameter Validation
Examine how expression strings are constructed and evaluated:
- **Look for**: Expression strings passed directly to **Suspicious Functions** without filtering
- **Missing validation**: No sanitization of expression content before **Suspicious Functions**
- **Dangerous operations**: **Suspicious Functions** can execute arbitrary Python code including exec/compile/etc
- **Builtins exposure**: All Python built-ins available to **Suspicious Functions** without restriction

#### 3. Expression Evaluation Pipeline
Analyze code paths that evaluate mathematical expressions:
- Where expressions originate from (user input, files, API parameters)
- Whether **Suspicious Functions** is called with unsanitized expression parameters
- No filtering of dangerous operations like **Suspicious Functions**
- No sandboxing or restricted evaluation context

### Query Patterns to Consider

- **Look for**: **Suspicious Functions**
- **Parameter sources**: Function parameters or untrusted input sources feeding into **Suspicious Functions**

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find eval calls
 * @description Finds all calls to the eval() function
 * @kind problem
 * @problem.severity error
 * @id py/find-eval-calls
 * @tags security
 *       injection
 *       code-execution
 */

import python

from Call c
where c.getFunc().(Name).getId() = "eval"
select c, "eval() call found"
```
