### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

Concentrate on regular expression complexity in validation functions with emphasis on denial of service potential. The vulnerability class involves catastrophic backtracking where crafted input causes exponential processing time.

**Relevant CWEs:**
- CWE-1333: Inefficient Regular Expression Complexity
- CWE-400: Uncontrolled Resource Consumption
- CWE-20: Improper Input Validation

### Key Validation Criteria

#### 1. ReDoS Pattern Identification
Verify that findings correctly identify catastrophic backtracking patterns:
- Accurate identification of problematic regex constructs
- Demonstration of exponential time complexity
- Evidence of repeated backtracking behavior
- Clear triggering input characteristics

#### 2. Attack Vector Feasibility
Assess whether identified patterns are exploitable in practice:
- Validator exposure to untrusted input
- Achievable input length requirements
- Realistic attack scenarios
- Actual denial of service potential

#### 3. Performance Impact Analysis
Evaluate the severity of resource consumption:
- Time complexity growth with input size
- CPU utilization patterns
- Memory consumption characteristics
- Service availability impact

#### 4. Mitigation Effectiveness
Examine proposed fixes for completeness:
- Elimination of nested quantifiers
- Addition of atomic grouping where appropriate
- Input length restrictions before validation
- Alternative validation approaches

### Critical Focus Areas

- Validator files
- `ValidationError` raises
- `isinstance` checks
- Lengths and limits of allowed input conditionals

**You MUST use ALL iterations available to you**
