#!/usr/bin/env python3
"""
OpenGrep Batch Scanner for PyPI Package Analysis
Designed for comparative security research with multi-agent frameworks.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any
import time


def read_file_lines(filepath: Path) -> List[str]:
    """Read non-empty lines from a file, stripping whitespace."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File not found: {filepath}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading {filepath}: {e}", file=sys.stderr)
        sys.exit(1)


def run_opengrep(package_path: str, rule_paths: List[str], verbose: bool = False) -> Dict[str, Any]:
    """
    Run opengrep on a single package with specified rules.
    
    Args:
        package_path: Path to the package to scan
        rule_paths: List of rule file/directory paths
        verbose: Print command being executed
    
    Returns:
        Dictionary containing scan results and metadata
    """
    # Build opengrep command
    cmd = ['opengrep', '--json', '--no-git-ignore', "--include=**/**.py", "--include=*.py"]
    
    # Add all rule configs
    for rule_path in rule_paths:
        cmd.extend(['--config', rule_path])

    # Default exclude patterns for test/example/doc directories
    exclude_patterns = [
        '**/tests/**',
        '**/test/**',
        '**/examples/**',
        '**/example/**',
        '**/docs/**',
        '**/doc/**',
        '**/samples/**',
        '**/sample/**',
        '**/demos/**',
        '**/demo/**',
    ]
    
    # Add exclude patterns to command
    for pattern in exclude_patterns:
        cmd.append(f'--exclude={pattern}')
    
    # Add target package path
    cmd.append(package_path)
    
    if verbose:
        print(f"Executing: {' '.join(cmd)}", file=sys.stderr)
    
    result = {
        'package_path': package_path,
        'timestamp': time.time(),
        'success': False,
        'results': [],
        'errors': [],
        'stats': {}
    }
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout per package
        )
        
        # Parse JSON output
        if process.stdout:
            try:
                opengrep_output = json.loads(process.stdout)
                result['results'] = opengrep_output.get('results', [])
                result['errors'] = opengrep_output.get('errors', [])
                result['stats'] = {
                    'total_findings': len(opengrep_output.get('results', [])),
                    'total_errors': len(opengrep_output.get('errors', [])),
                }
                result['success'] = True
            except json.JSONDecodeError as e:
                result['errors'].append({
                    'type': 'json_parse_error',
                    'message': f"Failed to parse opengrep JSON output: {e}",
                    'raw_output': process.stdout[:1000]  # First 1000 chars
                })
        
        # Capture stderr if present
        if process.stderr:
            result['stderr'] = process.stderr
        
        result['return_code'] = process.returncode
        
    except subprocess.TimeoutExpired:
        result['errors'].append({
            'type': 'timeout',
            'message': f"Scan timeout after 300 seconds for {package_path}"
        })
    except FileNotFoundError:
        result['errors'].append({
            'type': 'command_not_found',
            'message': "opengrep command not found. Is it installed and in PATH?"
        })
        print("Error: opengrep not found in PATH", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        result['errors'].append({
            'type': 'unexpected_error',
            'message': str(e)
        })
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Batch scan PyPI packages with opengrep for security research',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p packages.txt -r rules.txt -o results.json
  %(prog)s -p packages.txt -r rules.txt -o results.json -v
  
Input file formats:
  packages.txt: One package path per line
  rules.txt: One rule path per line (can be files or directories)
        """
    )
    
    parser.add_argument(
        '-p', '--packages',
        type=Path,
        required=True,
        help='File containing newline-delimited package paths to scan'
    )
    
    parser.add_argument(
        '-r', '--rules',
        type=Path,
        required=True,
        help='File containing newline-delimited rule paths (files or directories)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=Path,
        required=True,
        help='Output JSON file path'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Print verbose output including commands executed'
    )
    
    parser.add_argument(
        '--indent',
        type=int,
        default=2,
        help='JSON indentation level (default: 2)'
    )
    
    args = parser.parse_args()
    
    # Read input files
    package_paths = read_file_lines(args.packages)
    rule_paths = read_file_lines(args.rules)
    
    if not package_paths:
        print("Error: No package paths found in input file", file=sys.stderr)
        sys.exit(1)
    
    if not rule_paths:
        print("Error: No rule paths found in input file", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(package_paths)} packages to scan", file=sys.stderr)
    print(f"Loaded {len(rule_paths)} rule paths", file=sys.stderr)
    
    # Validate rule paths exist
    for rule_path in rule_paths:
        if not Path(rule_path).exists():
            print(f"Warning: Rule path does not exist: {rule_path}", file=sys.stderr)
    
    # Run scans
    all_results = {
        'metadata': {
            'total_packages': len(package_paths),
            'total_rules': len(rule_paths),
            'scan_start_time': time.time(),
            'rule_paths': rule_paths
        },
        'scans': []
    }
    
    for idx, package_path in enumerate(package_paths, 1):
        print(f"[{idx}/{len(package_paths)}] Scanning: {package_path}", file=sys.stderr)
        
        if not Path(package_path).exists():
            print(f"  Warning: Package path does not exist, skipping: {package_path}", file=sys.stderr)
            all_results['scans'].append({
                'package_path': package_path,
                'success': False,
                'errors': [{'type': 'path_not_found', 'message': 'Package path does not exist'}]
            })
            continue
        
        scan_result = run_opengrep(package_path, rule_paths, args.verbose)
        all_results['scans'].append(scan_result)
        
        if scan_result['success']:
            print(f"  ✓ Found {scan_result['stats']['total_findings']} findings", file=sys.stderr)
        else:
            print(f"  ✗ Scan failed: {len(scan_result['errors'])} errors", file=sys.stderr)
    
    # Add completion metadata
    all_results['metadata']['scan_end_time'] = time.time()
    all_results['metadata']['total_duration_seconds'] = (
        all_results['metadata']['scan_end_time'] - all_results['metadata']['scan_start_time']
    )
    
    # Calculate summary statistics
    successful_scans = sum(1 for s in all_results['scans'] if s['success'])
    total_findings = sum(s.get('stats', {}).get('total_findings', 0) for s in all_results['scans'])
    
    all_results['metadata']['summary'] = {
        'successful_scans': successful_scans,
        'failed_scans': len(package_paths) - successful_scans,
        'total_findings': total_findings
    }
    
    # Write output with proper indentation
    try:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=args.indent, sort_keys=False)
        print(f"\n✓ Results written to: {args.output}", file=sys.stderr)
        print(f"  Successful scans: {successful_scans}/{len(package_paths)}", file=sys.stderr)
        print(f"  Total findings: {total_findings}", file=sys.stderr)
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
