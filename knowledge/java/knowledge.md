# CodeQL Java/Kotlin Knowledge Schema for QRS

## Core Requirements
- Running CodeQL CLI v2.23.2 or later
- **ALWAYS** include @kind metadata property
- For @kind path-problem: MUST include @problem.severity AND import PathGraph
- For @kind problem: MUST include @problem.severity (values: error, warning, recommendation, note)
- Do NOT use @severity metadata property - it's deprecated and causes warnings
- A path-problem query MUST select from PathNode to PathNode and include edge parameter in select
- Path-problem select format: `select sink.getNode(), source, sink, "Message $@.", source.getNode(), "label"`
- Ensure correct number of columns in select based on @kind (path-problem needs PathNode results)

## Modern Data Flow API (Required - Legacy API deprecated)
- Use module signature pattern: `module MyConfig implements DataFlow::ConfigSig { ... }`
- For global data flow: `module MyFlow = DataFlow::Global<MyConfig>;`
- For global taint tracking: `module MyFlow = TaintTracking::Global<MyConfig>;`
- Implement `isSource(DataFlow::Node source)` and `isSink(DataFlow::Node sink)` predicates in config
- Optional: `isBarrier(DataFlow::Node node)` to block flow
- Optional: `isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2)` for custom steps
- Query flow: `MyFlow::flow(source, sink)` or for paths: `MyFlow::flowPath(source, sink)`

## Import Structure
- Core import: `import java` (imports ALL core Java/Kotlin library modules)
- For data flow: `import semmle.code.java.dataflow.DataFlow`
- For taint tracking: `import semmle.code.java.dataflow.TaintTracking`
- For remote flow sources: `import semmle.code.java.dataflow.FlowSources`
- For path queries: After flow module definition, add `import MyFlow::PathGraph`
- For string formatting: `import semmle.code.java.StringFormat`

## Program Elements (Java-specific)
- `Package` — Java package
- `CompilationUnit` — source file
- `Type` — all types (PrimitiveType, RefType, Class, Interface, EnumType, Array)
- `Method` — instance/static methods. Use `m.hasName("name")`, `m.getDeclaringType().hasQualifiedName("pkg", "Class")`
- `Constructor` — constructors. Use `c.getDeclaringType().hasQualifiedName("pkg", "Class")`
- `Callable` — superclass of Method and Constructor
- `Variable` — superclass of Field, LocalVariableDecl, Parameter
- `Field` — class fields (member variables)
- `Parameter` — method/constructor parameters

## Type System
- `PrimitiveType` — boolean, byte, char, double, float, int, long, short, void, nulltype
- `RefType` — reference types (Class, Interface, EnumType, Array)
- `TopLevelType` / `NestedType` — declaration scope
- `GenericType`, `ParameterizedType`, `RawType` — generics support
- `TypeVariable`, `TypeBound` — generic type parameters
- Singleton wrappers: `TypeObject`, `TypeString`, `TypeSystem`, `TypeClass`, `TypeSerializable`
- Check type: `v.getType() instanceof TypeString`, `t.hasQualifiedName("java.lang", "String")`
- Supertype: `nc.getASupertype() instanceof TypeObject`

## AST Nodes
- `Expr` — all expressions. Use `e.getAChildExpr()`, `e.getParent()`
- `Stmt` — all statements. Use `s.getAChild()`, `s.getParent()`
- Key statement types: `IfStmt`, `ReturnStmt`, `ForStmt`, `WhileStmt`, `TryStmt`, `ThrowStmt`, `SwitchStmt`, `Block`
- Key expression types: `MethodCall` (was MethodAccess), `FieldAccess`, `VarAccess`, `StringLiteral`, `ClassInstanceExpr` (new X()), `CastExpr`, `ArrayAccess`, `ThisAccess`, `SuperAccess`
- `MethodCall` predicates: `.getMethod()`, `.getQualifier()`, `.getArgument(i)`, `.getAnArgument()`
- `ClassInstanceExpr` (new): `.getConstructor()`, `.getArgument(i)`

## Data Flow Nodes
- `DataFlow::Node` — base class. Has `.asExpr()` for expressions, `.asParameter()` for parameters
- `DataFlow::ExprNode` — wraps an Expr. Create via `DataFlow::exprNode(expr)`
- `DataFlow::ParameterNode` — wraps a Parameter. Create via `DataFlow::parameterNode(p)`
- Convert: `node.asExpr()` returns the Expr, `node.asParameter()` returns the Parameter

## Sources and Sinks (Java)
- Remote sources: `source instanceof RemoteFlowSource` (from FlowSources module)
- Servlet request parameters: `source.asExpr().(MethodCall).getMethod().hasName("getParameter") and source.asExpr().(MethodCall).getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest")`
- File path sinks: `sink.asExpr() = call.getArgument(0) and call.getCallee().(Constructor).getDeclaringType().hasQualifiedName("java.io", "FileReader")`
- SQL injection sinks: `exists(MethodCall mc | mc.getMethod().hasName("execute") and mc.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.sql", "Statement") and sink.asExpr() = mc.getArgument(0))`
- Command execution sinks: `exists(MethodCall mc | mc.getMethod().hasName("exec") and mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and sink.asExpr() = mc.getArgument(0))`
- ProcessBuilder sinks: `exists(ClassInstanceExpr ce | ce.getConstructor().getDeclaringType().hasQualifiedName("java.lang", "ProcessBuilder") and sink.asExpr() = ce.getAnArgument())`
- Code injection (eval): `exists(MethodCall mc | mc.getMethod().hasName("eval") and mc.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.script", "ScriptEngine") and sink.asExpr() = mc.getArgument(0))`
- JNDI lookup sinks: `exists(MethodCall mc | mc.getMethod().hasName("lookup") and mc.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.naming", "Context") and sink.asExpr() = mc.getArgument(0))`
- Deserialization sinks: `exists(MethodCall mc | mc.getMethod().hasName("readObject") and mc.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.io", "ObjectInputStream") and sink.asExpr() = mc.getQualifier())`
- XSS sinks (Servlet response): `exists(MethodCall mc | mc.getMethod().hasName("write") and mc.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.io", "Writer") and sink.asExpr() = mc.getArgument(0))`
- Path traversal: `exists(ClassInstanceExpr ce | ce.getConstructor().getDeclaringType().hasQualifiedName("java.io", "File") and sink.asExpr() = ce.getArgument(0))`
- URL construction: `exists(ClassInstanceExpr ce | ce.getConstructor().getDeclaringType().hasQualifiedName("java.net", "URL") and sink.asExpr() = ce.getArgument(0))`

## Local Data Flow
- Local flow (within method): `DataFlow::localFlow(DataFlow::exprNode(src), DataFlow::exprNode(sink))`
- Local flow from parameter: `DataFlow::localFlow(DataFlow::parameterNode(p), DataFlow::exprNode(sink))`
- Local taint (with non-value-preserving steps): `TaintTracking::localTaint(DataFlow::exprNode(src), DataFlow::exprNode(sink))`

## Call Graph
- `Call` — all call expressions (method calls, new expressions, this/super calls)
- `call.getCallee()` — returns the Callable (Method or Constructor) being called
- `callable.getAReference()` — returns a Call that invokes this callable
- Find calls to named method: `exists(MethodCall mc | mc.getMethod().hasName("println") | ...)`
- Uncalled methods: `not exists(c.getAReference())`

## Annotations
- `Annotatable` — superclass of all annotatable elements
- `element.getAnAnnotation()` — get annotations on an element
- `Annotation` — an annotation instance. `.getType()` returns AnnotationType
- Find deprecated: `ann.getType().hasQualifiedName("java.lang", "Deprecated")`
- Find specific annotation: `ann.getType().hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")`

## Qualified Name Patterns (Common Packages)
- Standard library: `hasQualifiedName("java.lang", "Runtime")`, `hasQualifiedName("java.io", "File")`
- Servlet API: `hasQualifiedName("javax.servlet.http", "HttpServletRequest")`
- Spring: `hasQualifiedName("org.springframework.web.bind.annotation", "RequestMapping")`
- JNDI: `hasQualifiedName("javax.naming", "InitialContext")`
- XML: `hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")`
- Crypto: `hasQualifiedName("javax.crypto", "Cipher")`
- Reflection: `hasQualifiedName("java.lang.reflect", "Method")`
- For subtypes use: `getASupertype*().hasQualifiedName(...)` — the `*` means reflexive-transitive closure

## Efficiency and Correctness
- Always use `hasQualifiedName("package", "ClassName")` for precise type matching
- Use `getASupertype*()` to match subclasses and interface implementations
- For method calls, match on both method name AND declaring type to avoid false positives
- Prefer `MethodCall` over generic `Call` when looking for method invocations
- Use `exists()` for existential checks, `forall()` for universal checks
- Chain conditions with `and`, `or`, `not`
- Restrict queries to avoid overly broad results — combine method name, type, and argument count checks
