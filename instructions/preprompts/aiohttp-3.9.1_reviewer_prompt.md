### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for this async web framework, prioritize validation of:

#### Path Traversal & Directory Access
- **CWE-22**: Improper Limitation of a Pathname to a Restricted Directory
- **CWE-23**: Relative Path Traversal

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker control paths?** Are file paths from user input (URL, headers)?
- **What can be accessed?** Can arbitrary filesystem locations be reached?
- **Configuration dependent?** Does it require specific settings (e.g., follow_symlinks)?
- **Real-world deployments?** Is the vulnerable configuration commonly used?

#### 2. Context Analysis
- **Trace path handling**: User input → path construction → file access
- **Normalization checks**: How paths are sanitized before use
- **Symlink behavior**: When and how symlinks are followed
- **Boundary enforcement**: What prevents escape from static directory

#### 3. True Positive Indicators
- User-controlled paths can escape intended directory
- Relative path traversal (../) not properly blocked
- Symlink following enables unauthorized access
- Affects default or common configurations

#### 4. False Positive Indicators
- Requires non-default unsafe configuration
- Path validation properly prevents traversal
- Limited to intended directory with proper checks

### Critical Focus Areas

- Static file route handlers
- Path normalization and validation
- Symlink following configuration
- File access permission checks

**You MUST use ALL iterations available to you**
