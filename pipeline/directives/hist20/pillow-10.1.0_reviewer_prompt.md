### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for this image processing library, prioritize validation of:

#### Arbitrary Code Execution
- **CWE-94**: Improper Control of Generation of Code ('Code Injection')
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Can attacker control input?** Can expressions or environment be influenced?
- **What can be achieved?** Can arbitrary Python code be executed?
- **Which operations affected?** Does it impact image math evaluation?
- **Reachability?** Is the vulnerable function in common usage paths?

#### 2. Context Analysis
- **Trace evaluation flow**: User input → expression building → eval execution
- **Environment control**: How execution environment is configured
- **Expression validation**: Whether expressions are sanitized
- **Code execution paths**: From user data to eval operations

#### 3. True Positive Indicators
- User-controlled expressions evaluated without validation
- Environment parameter allows code injection
- Direct path from user input to eval/exec
- Affects common image processing APIs

#### 4. False Positive Indicators
- Expressions from trusted sources only
- Proper validation prevents code injection
- Sandboxed evaluation environment

### Critical Focus Areas

- Expression evaluation functions (ImageMath.eval)
- Environment parameter handling
- Expression validation and sanitization
- Code execution contexts

**You MUST use ALL iterations available to you**
