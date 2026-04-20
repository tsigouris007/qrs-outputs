CRITICAL - CodeQL Query Requirements:

## Core Requirements
- Running CodeQL CLI v2.23.2 or later
- **ALWAYS** include @kind metadata property
- For @kind path-problem: MUST include @problem.severity AND import PathGraph
- For @kind problem: MUST include @problem.severity (values: error, warning, recommendation, note)
- Do NOT use @severity metadata property - it's deprecated and causes warnings
- A path-problem query MUST select from PathNode to PathNode and include edge parameter in select
- Path-problem select format: `select sink.getNode(), source, sink, "Message $@.", source, "label"`
- Ensure correct number of columns in select based on @kind (path-problem needs PathNode results)

## Modern Data Flow API (Required - Legacy API deprecated)
- Use module signature pattern: `module MyConfig implements DataFlow::ConfigSig { ... }`
- For global data flow: `module MyFlow = DataFlow::Global<MyConfig>`
- For global taint tracking: `module MyFlow = TaintTracking::Global<MyConfig>`
- Implement `isSource(DataFlow::Node source)` and `isSink(DataFlow::Node sink)` predicates in config
- Optional: `isBarrier(DataFlow::Node node)` to block flow
- Optional: `isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2)` for custom steps
- Query flow: `MyFlow::flow(source, sink)` or for paths: `MyFlow::flowPath(source, sink)`

## Import Structure
- Core imports: `import python`, `import semmle.python.dataflow.new.DataFlow`, `import semmle.python.dataflow.new.TaintTracking`
- For API references: `import semmle.python.ApiGraphs`
- For predefined sources: `import semmle.python.dataflow.new.RemoteFlowSources`
- For security concepts: `import semmle.python.Concepts`
- For path queries: After flow module definition, add `import MyFlow::PathGraph`

## API Graph Usage (Preferred over syntactic matching)
- Module imports: `API::moduleImport("package_name")` (no dots allowed, decompose to .getMember)
- Accessing members: `.getMember("function_name")` or `.getMember(["opt1", "opt2"])` for multiple
- Getting calls: `.getACall()` returns API::CallNode (a DataFlow::Node with predicates)
- Getting return values: `.getReturn()` for function/constructor returns
- Built-in functions: `API::builtin("function_name")`
- Subclasses: `.getASubclass()` or `.getASubclass*()` for all descendants
- Class instances: Use dotted path ending in class name: `API::moduleImport("pkg.subpkg.ClassName")`
- Class itself (not instances): Add `!` suffix: `"pkg.ClassName!"`

## Data Flow Nodes
- Use `DataFlow::CallCfgNode` for function/method calls (NOT deprecated DataFlow::CallNode)
- Use `DataFlow::ExprNode` for expressions: `DataFlow::exprNode(expr)`
- Use `DataFlow::ParameterNode` for function parameters
- For local sources: Use `DataFlow::LocalSourceNode` and `.flowsTo()` predicate
- Convert between: `node.asExpr()` and `node.asCfgNode()`

## Sources and Sinks
- Remote sources: `source instanceof RemoteFlowSource` (from RemoteFlowSources module)
- File access sinks: `sink = any(FileSystemAccess fa).getAPathArgument()`
- Command execution: `sink = any(SystemCommandExecution cmd).getACommandArgument()`
- SQL execution: `sink = any(SqlExecution sql).getAnArgument()`
- Code execution: `sink instanceof CodeExecution`
- Path argument access: `call.getArg(0)` or `call.getParameter(0, "param_name")`

## Local Data Flow
- Local flow (within function): `DataFlow::localFlow(source, sink)`
- Local taint (with non-value-preserving steps): `TaintTracking::localTaint(source, sink)`
- Get local sources of node: `node.getALocalSource()`
- LocalSourceNode flow: `sourceNode.(DataFlow::LocalSourceNode).flowsTo(sinkNode)`

## Query Structure Best Practices
- Start with package profile analysis when possible
- Use `from` clause to declare typed variables: `from DataFlow::CallCfgNode call`
- Use `where` clause for conditions and predicates
- Chain API graph operations fluently: `API::moduleImport("os").getMember("system").getACall()`
- For path queries: Use `PathNode` type from imported PathGraph module
- Avoid syntactic `Call` and `Name` classes - prefer API graphs for library function references

## Common Patterns
- Finding calls to specific function: `call = API::moduleImport("module").getMember("func").getACall()`
- Checking call arguments: `call.getArg(0)` or `call.getParameter(0, "name")`
- Attribute access: `expr instanceof Attribute` with `.getObject()` and `.getAttribute()`
- Multiple conditions: Use `and`, `or`, `not`, `exists()`, `forall()`
- Comparison operators: Use `cmp.getOp(0)` and `cmp.getComparator(0)` for Compare expressions

## Efficiency and Correctness
- Focus queries on specific vulnerability patterns
- Use API graphs instead of syntactic pattern matching for library calls
- Restrict to LocalSourceNode when appropriate for performance
- Avoid overly broad queries that match everything
- Test queries return meaningful, actionable results
- Ensure syntactic correctness - queries must compile with CLI v2.23.2+
