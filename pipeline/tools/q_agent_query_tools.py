# Note: The code is not runnable and requires additional context and dependencies.
# The tools we are sharing in this file are execute_codeql_query and fixup_codeql_query.

import json
import os
from typing import List


QUERIES_DIR = "queries/" # Directory where CodeQL queries are stored
REPORTS_DIR = "reports/" # Directory where CodeQL results are stored


# As these are trivial utility functions they have been left as placeholders
def get_cur_timestamp():
  # Returns a pseudo-unique timestamp string for query identification
  pass


def run_command(command, timeout, logger):
  # Executes a system command using the subprocess module
  pass


class Executor:
  def execute_codeql_query(self,
                           codeql_query: str,
                           codeql_query_timeout: int = 600) -> dict:
    """
    Execute a CodeQL query against a database.
    """
    try:
      # Pseudo-unique filename
      codeql_query_uuid = get_cur_timestamp()
      queries_dir = QUERIES_DIR.replace("#LANG#", self.lang)
      codeql_query_path = f"{queries_dir}/{codeql_query_uuid}.ql"
      results_path = f"{REPORTS_DIR}/{self.package_name}/{codeql_query_uuid}_results.sarif"

      # Create package subdirectory if it doesn't exist
      os.makedirs(f"{REPORTS_DIR}/{self.package_name}", exist_ok=True)

      # Write query to a file in order to execute
      with open(codeql_query_path, "w") as f:
        f.write(codeql_query)

      # Run os command to execute the query
      command = [
        "codeql", "database", "analyze",
        self.database_path,
        codeql_query_path,
        "--format", "sarif-latest",
        "--threads", "1",
        "--ram", "8192",
        "--max-disk-cache", "0", # Disable disk caching to avoid issues with large results and ensure cleanup
        "--output", results_path
      ]
      run_command(command, timeout=codeql_query_timeout, logger=self.logger)

      # Check if results file was created
      if not os.path.exists(results_path):
        return {
          "success": False,
          "error": "CodeQL query compilation failed - no output generated",
          "results": [],
          "results_count": 0,
          "codeql_query_uuid": codeql_query_uuid
        }

      # Read the results from the SARIF file
      with open(results_path, "r") as f:
        sarif_results = f.read()
      results = json.loads(sarif_results)

      # Check execution status
      runs = results.get("runs", [])
      execution_successful = False
      if runs and len(runs) > 0:
        invocations = runs[0].get("invocations", [])
        if invocations and len(invocations) > 0:
          execution_successful = invocations[0].get("executionSuccessful", False)

      self.logger.info("[+] CodeQL query executed successfully." if execution_successful else "[-] CodeQL query execution failed.")

      if execution_successful:
        if runs:
          run_results = runs[0].get("results", [])
          # Skip noisy results
          if len(run_results) > 25:
            self.logger.info(f"[!] Query returned {len(run_results)} results, which exceeds the 25 result threshold. Skipping detailed results to avoid noise.")

            return {
              "success": False,
              "error": "Too many results returned meaning noisy output or too broad query (>25). Try again after refining the query. A small sample of your results is included.",
              "results": run_results[:5],
              "results_count": len(run_results),
              "codeql_query_uuid": codeql_query_uuid
            }

          # If we reach here, execution was successful with meaningful results
          return {
            "success": True,
            "error": None,
            "results": run_results,
            "results_count": len(run_results),
            "codeql_query_uuid": codeql_query_uuid
          }

      # If we reach here, execution was not successful
      return {
        "success": False,
        "error": "CodeQL query execution failed.",
        "results": [],
        "results_count": 0,
        "codeql_query_uuid": codeql_query_uuid
      }

    except Exception as e:
      return {
        "success": False,
        "error": str(e),
        "results": [],
        "results_count": 0,
        "codeql_query_uuid": None
      }

  def fixup_codeql_query(self,
                         codeql_query: str,
                         hypothesis: str = "",
                         cwe_ids: List[str] = [],
                         severity: str = "medium") -> dict:
    """
    Attempts to fix a CodeQL query that fails validation.
    Uses internal retries (max 3) without consuming agent iterations.
    """
    from pydantic import BaseModel

    class CodeQLQueryFix(BaseModel):
      codeql_query: str
      hypothesis: str
      cwe_ids: List[str]
      severity: str

    # Detect if using DeepSeek Reasoner (has limitations with structured outputs)
    is_reasoner = '-reasoner' in self.model.lower()
    
    schema = CodeQLQueryFix.model_json_schema()
    tools = [{
      "name": "structured_output",
      "description": "Return fixed CodeQL query",
      "input_schema": schema
    }]

    # Retrieve system prompt knowledge
    system_prompt_knowledge = self.retrieve_system_prompt_query_instructions()

    if is_reasoner:
      fixup_system_prompt = f"""You are a CodeQL query expert specializing in fixing syntax errors and deprecated API usage.
Your role is to fix broken CodeQL queries while maintaining their original intent.

{system_prompt_knowledge}
- Maintain the original hypothesis, CWE IDs and severity fields.

IMPORTANT: You must respond with ONLY a valid JSON object in this exact format (no markdown, no code blocks, no explanation):
{{"codeql_query": "your fixed query here", "hypothesis": "original hypothesis", "cwe_ids": ["list", "of", "cwe", "ids"], "severity": "severity level"}}"""
    else:
      fixup_system_prompt = f"""You are a CodeQL query expert specializing in fixing syntax errors and deprecated API usage.
Your role is to fix broken CodeQL queries while maintaining their original intent.

{system_prompt_knowledge}
- Maintain the original hypothesis, CWE IDs and severity fields."""

    retry_history = []
    max_retries = 3
    retries = 0

    while retries < max_retries:
      # Validate the query
      validation = self.executor.validate_codeql_query(codeql_query)

      if validation["valid"]:
        self.state.queries_executed += 1 # Count as executed query
        self.logger.info(f"[+] Query is valid (attempt {retries + 1}/{max_retries}).")
        return {
          "query": codeql_query,
          "valid": True,
          "error": None
        }
      else:
        self.state.queries_failed += 1
        self.logger.warning(f"[-] Query is invalid (attempt {retries + 1}/{max_retries}): {validation['error'][:1500]}")

        # Track failed attempt
        retry_history.append({
          "attempt": retries,
          "query": codeql_query,
          "error": validation['error']
        })

        # Build fixup prompt with retry history
        retry_context = ""
        if retry_history:
          retry_context = "\nPrevious failed attempts:\n"
          for attempt in retry_history:
            retry_context += f"\nAttempt {attempt['attempt']}:\n"
            retry_context += f"Error: {attempt['error'][:1500]}\n"

        fixup_prompt = f"""The following CodeQL query is invalid and fails to compile with CodeQL CLI v2.23.2.
Please fix the query to ensure it meets the requirements and compiles successfully.
Maintain the original hypothesis, CWE ID and severity.

Hypothesis: {hypothesis}
Severity: {severity}
CWE-IDs: {cwe_ids}

Query:
```
{codeql_query}
```

Error:
```
{validation['error']}
```
{retry_context}
"""
        messages = [
          {
            "role": "user",
            "content": fixup_prompt
          }
        ]

        try:
          # Reasoner needs different handling (no forced tool choice)
          if is_reasoner:
            response = self._call_llm(
              messages=messages,
              system=fixup_system_prompt,
              tools=None,  # No tools for reasoner
              tool_choice=None,
              max_tokens=self.max_tokens,
              temperature=self.temperature
            )
          else:
            response = self._call_llm(
              messages=messages,
              system=fixup_system_prompt,
              tools=tools,
              tool_choice={"type": "tool", "name": "structured_output"},
              max_tokens=self.max_tokens,
              temperature=self.temperature
            )

          # Track token usage from fixup calls (they burn tokens but don't consume iterations)
          self.state.total_input_tokens += response.usage.input_tokens
          self.state.total_output_tokens += response.usage.output_tokens
          self.logger.info(f"[*] Fixup call tokens - Input: {response.usage.input_tokens}, Output: {response.usage.output_tokens}")

          # Extract fixed query from response (handle both tool-based and text-based responses)
          if is_reasoner:
            # For Reasoner: extract JSON from text response
            text_block = next(
              (block for block in response.content if block.type == "text"),
              None
            )

            if text_block:
              response_text = text_block.text.strip()
              self.logger.info(f"[*] Reasoner response: {response_text[:200]}...")

              # Try to extract JSON from the response
              try:
                # Remove markdown code blocks if present
                if "```json" in response_text:
                  response_text = response_text.split("```json")[1].split("```")[0].strip()
                elif "```" in response_text:
                  response_text = response_text.split("```")[1].split("```")[0].strip()

                # Parse JSON
                fixed_data = json.loads(response_text)
                fixed_task = CodeQLQueryFix.model_validate(fixed_data)
                codeql_query = fixed_task.codeql_query
                self.logger.info(f"[*] Query updated with fixed version from Reasoner.")
              except (json.JSONDecodeError, ValueError) as parse_error:
                self.logger.warning(f"[-] Failed to parse Reasoner JSON response: {parse_error}")
                self.logger.warning(f"[-] Raw response: {response_text[:500]}")
                return {
                  "query": codeql_query,
                  "valid": False,
                  "error": f"Failed to parse reasoner response: {str(parse_error)}"
                }
            else:
              self.logger.warning(f"[-] No text block in Reasoner response")
              return {
                "query": codeql_query,
                "valid": False,
                "error": "No text response from reasoner"
              }
          else:
            # For other models: use structured output tool
            tool_use_block = next(
              (block for block in response.content if block.type == "tool_use"),
              None
            )

            if tool_use_block:
              fixed_task = CodeQLQueryFix.model_validate(tool_use_block.input)
              codeql_query = fixed_task.codeql_query
              self.logger.info(f"[*] Query updated with fixed version.")
            else:
              self.logger.warning(f"[-] No tool_use block in fixup response")
              return {
                "query": codeql_query,
                "valid": False,
                "error": "Failed to generate fix"
              }

        except Exception as e:
          self.logger.error(f"[-] Error fixing query: {str(e)}")
          return {
            "query": codeql_query,
            "valid": False,
            "error": f"Fixup failed: {str(e)}"
          }

        retries += 1

    # Failed after max retries
    self.logger.error(f"[-] Query failed validation after {retries} attempts.")
    return {
      "query": codeql_query,
      "valid": False,
      "error": f"Failed to fix after {max_retries} attempts"
    }
