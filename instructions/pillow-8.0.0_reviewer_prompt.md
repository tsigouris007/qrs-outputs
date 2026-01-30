### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for pillow's expression evaluation vulnerabilities, prioritize validation of:

#### Code Injection via Eval of Expressions
- **CWE-94**: Improper Control of Generation of Code
- **CWE-95**: Improper Neutralization of Directives in Dynamically Evaluated Code

### Key Validation Criteria

**Suspicious Functions**: eval/exec/compile/import

#### 1. Exploitability Assessment
- **Can attacker control input?** Can expression strings reach **Suspicious Functions**?
- **What can be achieved?** Do **Suspicious Functions** provide access to dangerous functions?
- **Context**: Is this in a public API?
- **Impact**: Can arbitrary Python code be executed through expression evaluation?

#### 2. Context Analysis
- **Trace data flow**: User input → expression string → eval() call
- **Expression construction**: How is the expression string built?
- **Input sources**: API parameters, file content, direct user input
- **Execution context**: What Python built-ins and operations are available in **Suspicious Functions**?
- **Missing restrictions**: Are **Suspicious Functions** callable through eval?

#### 3. True Positive Indicators
- **eval() with user-controlled expression**: **Suspicious Functions** called on expression strings from untrusted sources
- **Direct parameter mapping**: User input directly used as expression
- **Missing validation**: No sanitization/filtering of expression content before vulnerable functions
- **Unrestricted eval**: All Python built-ins available (exec, compile, __import__ callable)
- **Expression parameter untrusted**: Expression parameter originates from user input
- **Public API exposure**: Vulnerable through public functions

#### 4. False Positive Indicators
- Expression is hardcoded or from trusted internal source only
- All dangerous functions restricted
- Expression content validated/parsed to ensure
- Sandboxed or restricted Python execution environment
- Input validation prevents injection of arbitrary Python code

**You MUST use ALL iterations available to you**
