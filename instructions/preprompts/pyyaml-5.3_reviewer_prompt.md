### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for this YAML parsing library, prioritize validation of:

#### Code Execution & Deserialization Vulnerabilities
- **CWE-94**: Code Injection vulnerabilities
- **CWE-502**: Unsafe deserialization patterns
- **CWE-20**: Input validation issues leading to code execution

### Key Validation Criteria

#### 1. Exploitability Assessment
For each finding, thoroughly investigate:
- **Can attacker control the input?** Is the YAML input from untrusted sources?
- **What can be achieved?** Can arbitrary code execution be triggered through the finding?
- **What are the prerequisites?** Which loading functions or configurations enable the vulnerability?
- **Is it in the critical path?** Does it affect common/default usage patterns?

#### 2. Context Analysis
Carefully examine:
- **Code flows**: Trace from YAML input → parsing → object construction → execution
- **Function semantics**: Understand what each loading function does and its safety model
- **Default behavior**: Is the vulnerability present in default/recommended usage?
- **Attack vectors**: How would a real attacker craft malicious YAML to exploit this?

#### 3. True Positive Indicators
Strong signals for TRUE POSITIVE classification:
- Direct path from user-controlled YAML to code execution primitives
- Functions that deserialize and instantiate Python objects from YAML
- Dynamic code execution (`__import__`, `eval`, `exec`, object instantiation) triggered by parsed data
- Minimal prerequisites for exploitation
- Affects documented/common API usage patterns

#### 4. False Positive Indicators
Be cautious about marking as FALSE POSITIVE if:
- The code is in a constructor/loader component (likely intentional but potentially unsafe)
- Default behavior enables the vulnerability
- Common usage patterns are affected
- The library is designed to parse untrusted data

### Critical Focus Areas

Pay special attention to findings involving:
- YAML tag handlers for Python objects (`!!python/*`)
- Object constructors and deserializers
- Module import mechanisms during parsing
- Dynamic object instantiation from YAML structures

**You MUST use ALL iterations available to you**
