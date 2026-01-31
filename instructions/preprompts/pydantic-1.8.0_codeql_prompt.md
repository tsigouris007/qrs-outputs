### Priority Areas

Focus your security analysis on identifying missing bounds checks in numeric-to-datetime parsing:

#### 1. Infinity Value Handling while Parsing
- **CWE-835**: Infinite loop when parsing infinity values
- **CWE-400**: Resource exhaustion via unbounded numeric parsing
- Identify numeric parsing functions that accept float inputs (including special values)

#### 2. Specific Vulnerable Pattern
Look for functions that:
1. Accept float/numeric input values
2. Convert numeric values to objects
3. **LACK bounds checks** before performing conversion or iteration
4. Process special float values without validation

#### 3. Key Functions to Inspect
- Any function accepting numeric input for temporal field validation
- Numeric extraction from string representations of dates

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find timedelta usage
 * @description Finds all usages of timedelta
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-timedelta-usage
 * @tags datetime
 *       timedelta
 *       time
 */

import python

from Call c
where
  c.getFunc().(Name).getId() = "timedelta"
  or c.getFunc().(Attribute).getName() = "timedelta"
select c, "timedelta usage found"
```
