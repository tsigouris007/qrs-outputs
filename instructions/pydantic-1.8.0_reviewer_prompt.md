### Extra Instructions

You are receiving multiple interesting findings that are around locations with potential vulnerabilities. The findings might not be exactly there so you have to thoroughly look around find what is going on and why they were flagged. Use your tools in the best strategy possible to find actual vulnerable code snippets. You are **NOT** simply reviewing these findings and you should **NOT** stick only to them if they do not look vulnerable. You are actually getting guided and **MUST** find out on what is going on about the following criteria.

### Review Priority

When reviewing CodeQL findings for infinity-value handling while date parsing:

#### The Vulnerability Pattern CWEs
- **CWE-835**: Infinite loop when parsing infinity values
- **CWE-400**: Resource exhaustion via unbounded numeric parsing

### Key Validation Criteria

#### 1. Exploitability Assessment
- **Attacker Control**: Can untrusted input reach the parsing function?
- **Input Types**: Can attacker pass malicious strings?
- **Field Types**: Does the vulnerable code path affect fields?
- **Service Impact**: Does this cause CPU hang?

#### 3. True Positive Indicators
- Numeric parsing function lacks bounds validation before conversions
- Function accepts string values without special handling
- Conversion operations could receive infinity

#### 4. False Positive Indicators
- Bounds check exists before conversion
- Input validated to reject / sanitize values explicitly
- Conversions wrapped in try-except clauses
- Special values explicitly caught and converted

**You MUST use ALL iterations available to you**
