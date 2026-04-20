# Note: The code is not runnable and requires additional context and dependencies.
# The tools we are sharing in this file are extract_code_snippet, grep_search, and trace_dataflow_path.

import json
import os
import uuid


QUERIES_DIR = "queries/" # Directory where CodeQL queries are stored
REPORTS_DIR = "reports/" # Directory where CodeQL results are stored
PACKAGES_DIR = "packages/" # Directory where package source code is stored


# As these are trivial utility functions they have been left as placeholders
def get_cur_timestamp():
  # Returns a pseudo-unique timestamp string for query identification
  pass


def run_command(command, timeout, logger):
  # Executes a system command using the subprocess module
  pass


def cleanup_file(file_path):
  # Deletes a file if it exists
  pass


class Executor:
  def extract_code_snippet(self,
                          file_path: str,
                          start_line: int,
                          end_line: int) -> dict:
    """
    Extract code snippet from file.
    """
    try:
      full_path = os.path.join(self.package_path, file_path)

      with open(full_path, 'r') as f:
        lines = f.readlines()

      total_lines = len(lines)

      # Validate and bound line numbers
      actual_start = max(1, min(start_line, total_lines))
      actual_end = max(1, min(end_line, total_lines))

      self.logger.info(f"[*] Extracting {file_path}:{actual_start}-{actual_end}")

      # Extract lines
      extracted = lines[actual_start - 1:actual_end]
      code_snippet = ''.join(extracted)

      return {
        "success": True,
        "code": code_snippet,
        "start_line": actual_start,
        "end_line": actual_end,
        "total_lines": total_lines,
        "error": None
      }

    except Exception as e:
      self.logger.error(f"[-] Failed to extract code from {file_path}: {str(e)}")
      return {
        "success": False,
        "code": None,
        "start_line": None,
        "end_line": None,
        "total_lines": None,
        "error": f"Error extracting code: {str(e)}"
      }

  def grep_search(self,
                  pattern: str,
                  directory: str = "") -> dict:
    """
    Grep for a pattern in the package files. If directory is set it looks below this directory.
    """
    # Build search path - if directory provided, search within it, otherwise search entire package
    if directory and directory != "":
      search_path = os.path.join(f"{PACKAGES_DIR}/{self.package_name}", directory)
    else:
      search_path = f"{PACKAGES_DIR}/{self.package_name}"

    if self.lang == "python":
      search_regex = "--include=*.py"
    elif self.lang == "java":
      search_regex = "--include=*.java"
    else:
      raise ValueError(f"Unsupported language for grep search: {self.lang}")

    command = [
      "grep",
      "-rn",
      pattern,
      search_path,
      search_regex
    ]
    results = run_command(command, timeout=60, logger=self.logger, capture_output=True)

    matches = []
    for line in results.stdout.strip().split('\n'):
      if not line: continue
      parts = line.split(":", 2)
      matches.append({
        "file": parts[0].replace(f"{PACKAGES_DIR}/", "").replace(f"{self.package_name}/", ""),
        "line": int(parts[1]),
        "content": parts[2]
      })

    return {
      "matches": matches,
      "total": len(matches)
    }

  def trace_dataflow_path(self,
                          source_file: str,
                          source_line: int,
                          sink_file: str,
                          sink_line: int,
                          line_tolerance: int = 1) -> dict:
    """
    Trace dataflow path from source to sink using CodeQL path query.

    Args:
      source_file: Source file path (relative to package root)
      source_line: Source line number
      sink_file: Sink file path (relative to package root)
      sink_line: Sink line number
      line_tolerance: Number of lines above/below to consider for source/sink matching. Number of lines above/below to search via CodeQL. Keep this value really low (1-3) to avoid false positives.
    Returns:
      dict with success, flow_path (list of nodes) or flow_paths (list of paths), or error
    """

    # Build templated path query
    if self.lang == "python":
      path_query = f"""
/**
* @name Dataflow path query
* @description Traces dataflow from specified source to sink
* @kind path-problem
* @problem.severity error
* @id python/dataflow-path-trace
*/

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

module PathTraceConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    exists(Location loc |
    loc = source.getLocation() and
    loc.getFile().getRelativePath() = "{source_file}" and
    loc.getStartLine() >= {source_line - line_tolerance} and
    loc.getStartLine() <= {source_line + line_tolerance}
    )
  }}

  predicate isSink(DataFlow::Node sink) {{
    exists(Location loc |
    loc = sink.getLocation() and
    loc.getFile().getRelativePath() = "{sink_file}" and
    loc.getStartLine() >= {sink_line - line_tolerance} and
    loc.getStartLine() <= {sink_line + line_tolerance}
    )
  }}
}}

module PathTraceFlow = TaintTracking::Global<PathTraceConfig>;
import PathTraceFlow::PathGraph

from PathTraceFlow::PathNode source, PathTraceFlow::PathNode sink
where PathTraceFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Dataflow path from source to sink"
  """
    elif self.lang == "java":
      path_query = f"""
/**
 * @name Dataflow path query
 * @description Traces dataflow from specified source to sink
 * @kind path-problem
 * @problem.severity error
 * @id java/dataflow-path-trace
 */
 
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
 
module PathTraceConfig implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node source) {{
    exists(Location loc |
      loc = source.getLocation() and
      loc.getFile().getRelativePath().matches("%{source_file}") and
      loc.getStartLine() >= {source_line - line_tolerance} and
      loc.getStartLine() <= {source_line + line_tolerance}
    )
  }}
 
  predicate isSink(DataFlow::Node sink) {{
    exists(Location loc |
      loc = sink.getLocation() and
      loc.getFile().getRelativePath().matches("%{sink_file}") and
      loc.getStartLine() >= {sink_line - line_tolerance} and
      loc.getStartLine() <= {sink_line + line_tolerance}
    )
  }}
}}
 
module PathTraceFlow = TaintTracking::Global<PathTraceConfig>;
import PathTraceFlow::PathGraph
 
from PathTraceFlow::PathNode source, PathTraceFlow::PathNode sink
where PathTraceFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Dataflow path from source to sink"
  """
    else:
      raise ValueError(f"Unsupported language for dataflow tracing: {self.lang}")

    self.logger.info(f"[*] Tracing dataflow path from: {source_file}:{source_line} to {sink_file}:{sink_line} with line tolerance {line_tolerance}")

    # Pseudo-unique filename
    codeql_query_uuid = str(uuid.uuid4())
    queries_dir = QUERIES_DIR.replace("#LANG#", self.lang)
    codeql_query_path = f"{queries_dir}/{codeql_query_uuid}.ql"
    results_path = f"{REPORTS_DIR}/{codeql_query_uuid}_results.sarif"

    # Write query to a file to execute
    with open(codeql_query_path, "w") as f:
      f.write(path_query)

    # Run os command to execute the query
    command = [
      "codeql", "database", "analyze",
      self.database_path,
      codeql_query_path,
      "--format", "sarif-latest",
      "--output", results_path,
      "--threads", "1"
    ]
    run_command(command, timeout=300, logger=self.logger)

    # Check if results file was created
    if not os.path.exists(results_path):
      cleanup_file(codeql_query_path)
      return {
        "success": False,
        "error": "CodeQL query compilation failed - no output generated",
      }

    # Read results
    with open(results_path, "r") as f:
      sarif_results = f.read()
    results = json.loads(sarif_results)

    # Cleanup
    cleanup_file(codeql_query_path)
    cleanup_file(results_path)

    # Check execution status
    runs = results.get("runs", [])
    execution_successful = False
    if runs and len(runs) > 0:
      invocations = runs[0].get("invocations", [])
      if invocations and len(invocations) > 0:
        execution_successful = invocations[0].get("executionSuccessful", False)

    self.logger.info("[+] CodeQL query executed successfully." if execution_successful else "[-] CodeQL query execution failed.")

    if not execution_successful:
      self.logger.info("[-] CodeQL query execution failed.")
      return {
        "success": False,
        "error": "CodeQL query execution failed",
      }

    run_results = runs[0].get("results", [])
    if len(run_results) == 0:
      self.logger.info("[-] No dataflow paths found by CodeQL.")
      return {
        "success": False,
        "error": f"CodeQL fetched no dataflow path from {source_file}:{source_line} to {sink_file}:{sink_line}. This could mean: (1) no dataflow exists between these points or (2) the line numbers are incorrect or (3) the locations are not on dataflow boundaries."
      }

    self.logger.info(f"[+] CodeQL found {len(run_results)} results.")

    self.logger.info(f"[+] Found {len(run_results)} dataflow paths from {source_file}:{source_line} to {sink_file}:{sink_line}.")

    # Check for excessive paths
    if len(run_results) > 10:
      self.logger.info("[!] More than 10 dataflow paths found meaning noise.")
      return {
        "success": False,
        "error": "Too many dataflow paths returned (>10). Please try again with a smaller line_tolerance value.",
        "results": None
      }

    return {
      "success": True,
      "paths_found": len(run_results),
      "results": run_results
    }
