### Priority Areas

Focus your security analysis on the following high-priority vulnerability classes relevant to image processing libraries:

#### 1. Code Execution Vulnerabilities
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')
- Look for unsafe evaluation of user-controlled expressions

#### 2. Expression Evaluation Patterns
- Examine functions that evaluate mathematical expressions
- Investigate environment parameter handling
- Check for code execution through eval-like operations

#### 3. Dynamic Code Execution
- Functions that evaluate strings as code
- User-controlled parameters in eval contexts
- Environment manipulation for code execution

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
