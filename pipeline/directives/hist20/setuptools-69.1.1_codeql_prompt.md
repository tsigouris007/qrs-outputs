### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Priority Areas

Focus your security analysis on package download and URL handling:

#### 1. Command Injection in Download Operations
- **CWE-94**: Improper Control of Generation of Code
- **CWE-78**: Improper Neutralization of Special Elements in Commands
- Identify download functions that construct commands from URLs

#### 2. Vulnerable Pattern: URLs in Command Construction
Search for download/fetch logic that:
1. Accepts package URLs as input
2. Constructs system commands with those URLs
3. Executes commands via shell or subprocess
4. May NOT validate/escape URL metacharacters

#### 3. Key Points
- Package download methods
- VCS handling functions (git, hg, svn, etc.)
- URL parsing before command construction
- Shell command execution with URLs
- **Important** functions that download files externally (look for `download` in their names) that may introduce RCE
- You can try enumerating methods that exist in interesting files that may look relevant
- You can try using simple queries

**You MUST use ALL iterations available to you**

##### Example

**IMPORTANT NOTE**: These are example queries to help you structure your queries based on the above criteria. If you already have information you need there is no need to run these queries directly. Feel free to be creative and craft whatever is necessary in order to pinpoint potential vulnerable locations.

```ql
/**
 * @name Find download functions in specific file
 * @description Finds all functions containing 'download' in their name within a specific file
 * @kind problem
 * @problem.severity recommendation
 * @id py/find-download-functions-in-file
 * @tags functions
 *       naming
 */

import python

from Function f
where 
  f.getName().toLowerCase().matches("%download%")
  and f.getLocation().getFile().getBaseName() = "<file_of_interest>.py"
select f, "Function containing 'download': " + f.getName()
```
