## Objective
Identify potential memory safety issues in cipher operations related to buffer protocol implementation and writeability validation.

## Key Pattern to Find
Look for code that:
1. Accepts Python objects implementing the buffer protocol (via `from_buffer()` or similar FFI buffer operations)
2. Passes these buffers to operations that modify/write data
3. **Does NOT explicitly verify buffer writeability** before using them for write operations

## Search Terms
- `from_buffer` (FFI buffer creation)
- `cipher`, `encryptor`, `decryptor` (cipher operations)
- `update_into` or similar output buffer parameters
- `hazmat/backends` (backend implementations)

## Pattern to Highlight
Focus on methods that:
- Accept a buffer parameter intended for output/writing
- Create CFFI buffer objects from the Python parameter
- Perform write operations through these buffers
- Check: Are there buffer mutability or writeability checks?

## Why This Matters
Methods that write to buffers from Python objects must validate that the buffer is writable. Without this check, immutable objects can be corrupted, leading to data corruption and undefined behavior.

## CWE Reference
CWE-754: Improper Check for Unusual or Exceptional Conditions

**You MUST use ALL iterations available to you**

#### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find from_buffer calls in subfolder
 * @description Finds all calls to 'from_buffer' within a specific subfolder path
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-from-buffer-calls
 * @tags calls
 *       security
 */

import python

from Call c
where
  c.getFunc().(Attribute).getName() = "from_buffer"
  and c.getLocation().getFile().getRelativePath().matches("<your>/<path>/%")
select c, "Call to 'from_buffer' found at " + c.getLocation().getFile().getRelativePath()
```
