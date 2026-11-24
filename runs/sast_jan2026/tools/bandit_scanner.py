#!/usr/bin/env python3
"""
Bandit Batch Scanner for PyPI Package Analysis
Designed for comparative security research with multi-agent frameworks.
Companion script to opengrep_batch_scanner.py for thesis comparison.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any
import time
import re


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


def extract_json_from_output(output: str) -> str:
    """
    Extract JSON from bandit output that may contain progress bars or other text.
    
    Args:
        output: Raw output from bandit
        
    Returns:
        Cleaned JSON string
    """
    # Find the first '{' and last '}' to extract JSON
    first_brace = output.find('{')
    last_brace = output.rfind('}')
    
    if first_brace != -1 and last_brace != -1 and first_brace < last_brace:
        return output[first_brace:last_brace + 1]
    
    return output


def run_bandit(package_path: str, verbose: bool = False) -> Dict[str, Any]:
    """
    Run bandit on a single package via Docker.
    
    Args:
        package_path: Path to the package to scan
        verbose: Print command being executed
    
    Returns:
        Dictionary containing scan results and metadata
    """
    package_path_obj = Path(package_path).resolve()
    
    # Build docker command
    # Mount the package directory as read-only
    # Bandit will scan /src inside the container
    cmd = [
        'docker', 'run', '--rm',
        '-v', f'{package_path_obj}:/src:ro',
        'ghcr.io/pycqa/bandit/bandit',
        '-r', '/src',
        '-f', 'json',
        '--skip', 'B404,B603',  # Skip common noisy checks (import subprocess, subprocess without shell=True)
        '--exclude', '/src/tests,/src/test,/src/examples,/src/example,/src/docs,/src/doc,/src/samples,/src/sample,/src/demos,/src/demo'
    ]
    
    if verbose:
        print(f"Executing: {' '.join(cmd)}", file=sys.stderr)
    
    result = {
        'package_path': str(package_path_obj),
        'timestamp': time.time(),
        'success': False,
        'results': [],
        'errors': [],
        'stats': {},
        'metrics': {}
    }
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout per package
        )
        
        # Parse JSON output from stdout
        if process.stdout:
            try:
                # Extract JSON from potentially mixed output (progress bars, etc.)
                json_output = extract_json_from_output(process.stdout)
                
                if not json_output.strip():
                    raise ValueError("No JSON content found in output")
                
                bandit_output = json.loads(json_output)
                
                # Extract results
                result['results'] = bandit_output.get('results', [])
                result['errors'] = bandit_output.get('errors', [])
                
                # Extract metrics for comparison
                metrics = bandit_output.get('metrics', {})
                result['metrics'] = metrics
                
                # Calculate number of files scanned (exclude _totals)
                files_scanned = len([k for k in metrics.keys() if k != '_totals'])
                
                # Get totals
                totals = metrics.get('_totals', {})
                
                # Calculate stats comparable to opengrep
                result['stats'] = {
                    'total_findings': len(bandit_output.get('results', [])),
                    'total_errors': len(bandit_output.get('errors', [])),
                    'files_scanned': files_scanned,
                    'loc_analyzed': totals.get('loc', 0),
                    'nosec_count': totals.get('nosec', 0),
                }
                
                # Add severity breakdown
                severity_counts = {}
                confidence_counts = {}
                for finding in result['results']:
                    severity = finding.get('issue_severity', 'UNDEFINED')
                    confidence = finding.get('issue_confidence', 'UNDEFINED')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
                
                result['stats']['severity_breakdown'] = severity_counts
                result['stats']['confidence_breakdown'] = confidence_counts
                
                result['success'] = True
                
            except json.JSONDecodeError as e:
                result['errors'].append({
                    'type': 'json_parse_error',
                    'message': f"Failed to parse bandit JSON output: {e}",
                    'raw_output': process.stdout[:2000]  # Increased to 2000 chars for debugging
                })
            except ValueError as e:
                result['errors'].append({
                    'type': 'no_json_found',
                    'message': str(e),
                    'raw_output': process.stdout[:2000]
                })
            except Exception as e:
                result['errors'].append({
                    'type': 'stats_calculation_error',
                    'message': f"Error calculating stats: {str(e)}"
                })
        else:
            result['errors'].append({
                'type': 'no_output',
                'message': "Bandit produced no output"
            })
        
        # Capture stderr if present (usually contains summary)
        if process.stderr:
            result['stderr'] = process.stderr
        
        result['return_code'] = process.returncode
        
    except subprocess.TimeoutExpired:
        result['errors'].append({
            'type': 'timeout',
            'message': f"Scan timeout after 600 seconds for {package_path}"
        })
    except FileNotFoundError:
        result['errors'].append({
            'type': 'docker_not_found',
            'message': "docker command not found. Is Docker installed and in PATH?"
        })
        print("Error: docker not found in PATH", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        result['errors'].append({
            'type': 'unexpected_error',
            'message': str(e)
        })
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Batch scan PyPI packages with Bandit (via Docker) for security research',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p packages.txt -o bandit_results.json
  %(prog)s -p packages.txt -o bandit_results.json -v
  
Input file format:
  packages.txt: One package path per line (absolute paths recommended)
  
Notes:
  - Bandit runs in Docker container (ghcr.io/pycqa/bandit/bandit image)
  - Automatically excludes test/example/doc directories
  - Output format matches opengrep_batch_scanner.py for comparison
        """
    )
    
    parser.add_argument(
        '-p', '--packages',
        type=Path,
        required=True,
        help='File containing newline-delimited package paths to scan'
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
    
    # Verify Docker is available
    try:
        docker_check = subprocess.run(
            ['docker', '--version'],
            capture_output=True,
            timeout=5
        )
        if docker_check.returncode != 0:
            print("Error: Docker is not running or not accessible", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Error: Cannot verify Docker installation: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Verify Bandit Docker image is available
    try:
        image_check = subprocess.run(
            ['docker', 'images', '-q', 'ghcr.io/pycqa/bandit/bandit'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if not image_check.stdout.strip():
            print("Warning: ghcr.io/pycqa/bandit/bandit image not found locally", file=sys.stderr)
            print("Pulling image... (this may take a minute)", file=sys.stderr)
            subprocess.run(['docker', 'pull', 'ghcr.io/pycqa/bandit/bandit'], check=True)
    except Exception as e:
        print(f"Warning: Could not verify bandit image: {e}", file=sys.stderr)
    
    # Read input file
    package_paths = read_file_lines(args.packages)
    
    if not package_paths:
        print("Error: No package paths found in input file", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(package_paths)} packages to scan", file=sys.stderr)
    print(f"Using Docker image: ghcr.io/pycqa/bandit/bandit", file=sys.stderr)
    print(f"Excluding: tests, examples, docs, samples, demos directories", file=sys.stderr)
    
    # Validate package paths exist
    for package_path in package_paths:
        if not Path(package_path).exists():
            print(f"Warning: Package path does not exist: {package_path}", file=sys.stderr)
    
    # Run scans
    all_results = {
        'metadata': {
            'tool': 'bandit',
            'tool_version': 'ghcr.io/pycqa/bandit/bandit (Docker)',
            'total_packages': len(package_paths),
            'scan_start_time': time.time(),
            'exclude_patterns': [
                '**/tests/**', '**/test/**',
                '**/examples/**', '**/example/**',
                '**/docs/**', '**/doc/**',
                '**/samples/**', '**/sample/**',
                '**/demos/**', '**/demo/**'
            ]
        },
        'scans': []
    }
    
    for idx, package_path in enumerate(package_paths, 1):
        print(f"\n[{idx}/{len(package_paths)}] Scanning: {package_path}", file=sys.stderr)
        
        if not Path(package_path).exists():
            print(f"  Warning: Package path does not exist, skipping", file=sys.stderr)
            all_results['scans'].append({
                'package_path': package_path,
                'success': False,
                'errors': [{'type': 'path_not_found', 'message': 'Package path does not exist'}]
            })
            continue
        
        scan_result = run_bandit(package_path, args.verbose)
        all_results['scans'].append(scan_result)
        
        if scan_result['success']:
            stats = scan_result['stats']
            print(f"  ✓ Scanned {stats.get('files_scanned', 0)} files, "
                  f"found {stats['total_findings']} findings", file=sys.stderr)
            if stats.get('severity_breakdown'):
                severity_str = ', '.join(f"{k}: {v}" for k, v in stats['severity_breakdown'].items())
                print(f"    Severity breakdown: {severity_str}", file=sys.stderr)
            print(f"    Lines of code analyzed: {stats.get('loc_analyzed', 0)}", file=sys.stderr)
        else:
            print(f"  ✗ Scan failed: {len(scan_result['errors'])} errors", file=sys.stderr)
            if scan_result['errors'] and args.verbose:
                for error in scan_result['errors']:
                    print(f"    Error: {error.get('message', 'Unknown error')}", file=sys.stderr)
    
    # Add completion metadata
    all_results['metadata']['scan_end_time'] = time.time()
    all_results['metadata']['total_duration_seconds'] = (
        all_results['metadata']['scan_end_time'] - all_results['metadata']['scan_start_time']
    )
    
    # Calculate summary statistics
    successful_scans = sum(1 for s in all_results['scans'] if s['success'])
    total_findings = sum(s.get('stats', {}).get('total_findings', 0) for s in all_results['scans'])
    total_files = sum(s.get('stats', {}).get('files_scanned', 0) for s in all_results['scans'])
    total_loc = sum(s.get('stats', {}).get('loc_analyzed', 0) for s in all_results['scans'])
    
    # Aggregate severity breakdown across all scans
    total_severity = {}
    total_confidence = {}
    for scan in all_results['scans']:
        if scan.get('success'):
            for severity, count in scan.get('stats', {}).get('severity_breakdown', {}).items():
                total_severity[severity] = total_severity.get(severity, 0) + count
            for confidence, count in scan.get('stats', {}).get('confidence_breakdown', {}).items():
                total_confidence[confidence] = total_confidence.get(confidence, 0) + count
    
    all_results['metadata']['summary'] = {
        'successful_scans': successful_scans,
        'failed_scans': len(package_paths) - successful_scans,
        'total_findings': total_findings,
        'total_files_scanned': total_files,
        'total_loc_analyzed': total_loc,
        'severity_breakdown': total_severity,
        'confidence_breakdown': total_confidence
    }
    
    # Write output with proper indentation
    try:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=args.indent, sort_keys=False)
        print(f"\n✓ Results written to: {args.output}", file=sys.stderr)
        print(f"  Successful scans: {successful_scans}/{len(package_paths)}", file=sys.stderr)
        print(f"  Total files scanned: {total_files}", file=sys.stderr)
        print(f"  Total LOC analyzed: {total_loc}", file=sys.stderr)
        print(f"  Total findings: {total_findings}", file=sys.stderr)
        if total_severity:
            severity_str = ', '.join(f"{k}: {v}" for k, v in sorted(total_severity.items()))
            print(f"  Severity breakdown: {severity_str}", file=sys.stderr)
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
