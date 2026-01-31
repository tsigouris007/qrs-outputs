### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for this template engine, prioritize validation of sandbox escaping related issues:

#### Sandbox Escape & Code Injection
- **CWE-94**: Code Injection vulnerabilities
- **CWE-184**: Incomplete List of Disallowed Inputs

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker control template content?** Are templates processed from untrusted sources?
- **What can be achieved?** Can the sandbox be escaped to execute arbitrary code?
- **What are the prerequisites?** Which template features enable the vulnerability?
- **Is sandboxed mode affected?** Does it bypass intended security restrictions?

#### 2. Context Analysis
- **Trace template evaluation**: Input → parsing → filter application → execution
- **Check sandbox enforcement**: What security boundaries exist and how are they bypassed?
- **Attribute access chains**: Can template syntax reach dangerous Python methods?

#### 3. True Positive Indicators
- Direct path from template input to unrestricted Python code execution
- Filter operations that expose dangerous object methods
- Attribute access bypassing sandbox restrictions
- Affects sandboxed template execution

#### 4. False Positive Indicators
- Only exploitable with unsafe/non-sandboxed configuration
- Requires direct Python API access, not template syntax
- Intended behavior in non-sandboxed contexts

### Critical Focus Areas

- Filter implementations (especially attribute/method access filters)
- Sandboxed environment implementation
- Look around sandbox, and filtering code
- Object attribute resolution mechanisms
- Format string operations in templates

**You MUST use ALL iterations available to you**
