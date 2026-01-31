### Priority Areas

Focus CodeQL analysis on static file serving mechanisms and path resolution logic. The primary concern involves directory traversal where user-controlled paths may escape intended boundaries.

**Relevant CWEs:**
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory
- CWE-23: Relative Path Traversal

### Analysis Strategy

#### 1. Path Resolution and Validation
Examine how file paths are constructed and validated in static file handlers:
- Path normalization and canonicalization logic
- Relative path component handling (../ sequences)
- Symlink resolution and following behavior
- Security boundary enforcement mechanisms

#### 2. Static File Handler Implementation
Investigate the static file serving infrastructure:
- Route handlers that serve files based on URL paths
- Configuration parameters affecting file access behavior
- Directory traversal prevention mechanisms
- Base directory restriction enforcement

#### 3. Symlink Following Controls
Analyze symlink handling security:
- Conditional symlink following based on configuration
- Symlink target validation
- Checks preventing symlink-based directory escape
- Interaction between symlink following and path restrictions

#### 4. Taint Tracking Approach
Write CodeQL queries that track:
- Data flow from request URL/path parameters
- Through path joining and resolution operations
- To filesystem access operations (open, read, stat)
- Identify missing sanitization between source and sink

### Critical Focus Areas

Write CodeQL queries using taint tracking to identify paths where URL-derived file paths flow to filesystem operations without adequate validation. Focus on handlers that serve static content and examine how they construct file paths from request data. Pay attention to configuration flags that affect symlink behavior and whether they create security gaps.

**You MUST use ALL iterations available to you**

### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find follow_symlinks parameter
 * @description Finds all usages of the follow_symlinks parameter in function calls
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-follow-symlinks-parameter
 * @tags security
 *       filesystem
 *       symlinks
 */

import python

from Call c, Keyword k
where
  k = c.getAKeyword()
  and k.getArg() = "follow_symlinks"
select c, "Call with follow_symlinks parameter found"
```
