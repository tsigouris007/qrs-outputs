#!/usr/bin/env python3
"""
CodeQL Batch Scanner for PyPI Package Analysis
Designed for comparative security research with multi-agent frameworks.
Uses codeql/python-queries qlpack for analysis.
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


def run_codeql(package_name: str, db_path: str, qlpack_root: Path, sarif_output: Path, verbose: bool = False) -> Dict[str, Any]:
    """
    Run CodeQL on a single package database using qlpack.
    
    Args:
        package_name: Name of the package being analyzed
        db_path: Path to the CodeQL database
        qlpack_root: Root directory containing the qlpack (codeql/python/ql/src)
        sarif_output: Path to write SARIF output
        verbose: Print detailed output
    
    Returns:
        Dictionary containing scan results and metadata
    """
    result = {
        'package_name': package_name,
        'package_path': db_path,
        'timestamp': time.time(),
        'success': False,
        'findings': [],
        'errors': [],
        'stats': {
            'total_findings': 0,
        }
    }
    
    # Build CodeQL command using qlpack
    # The qlpack name is 'codeql/python-queries' as defined in qlpack.yml
    cmd = [
        'codeql-cli', 'database', 'analyze',
        '--format=sarif-latest',
        f'--output={sarif_output}',
        db_path,
        'codeql/python-queries'
    ]
    
    # Set environment to include the qlpack search path
    env = subprocess.os.environ.copy()
    env['CODEQL_SEARCHPATH'] = str(qlpack_root.parent.parent)  # /home/.../codeql/python/ql
    
    if verbose:
        print(f"  Command: {' '.join(cmd)}", file=sys.stderr)
        print(f"  CODEQL_SEARCHPATH: {env['CODEQL_SEARCHPATH']}", file=sys.stderr)
    
    try:
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minute timeout per package
            env=env
        )
        
        if process.returncode == 0 and sarif_output.exists():
            try:
                with open(sarif_output, 'r') as f:
                    sarif_data = json.load(f)
                
                # Extract findings from SARIF format
                findings = []
                total_findings = 0
                
                if 'runs' in sarif_data:
                    for run in sarif_data['runs']:
                        if 'results' in run:
                            findings.extend(run['results'])
                            total_findings += len(run['results'])
                
                result['findings'] = findings
                result['stats']['total_findings'] = total_findings
                result['success'] = True
                
            except json.JSONDecodeError as e:
                result['errors'].append({
                    'type': 'json_parse_error',
                    'message': f"Failed to parse SARIF output: {e}"
                })
        else:
            # CodeQL exited with error
            if process.stderr:
                # Try to extract meaningful error message
                err_lines = process.stderr.split('\n')
                error_msg = '\n'.join(err_lines[-10:]) if len(err_lines) > 10 else process.stderr
                result['errors'].append({
                    'type': 'codeql_error',
                    'message': error_msg[:500]
                })
            else:
                result['errors'].append({
                    'type': 'codeql_failed',
                    'message': f"CodeQL exited with code {process.returncode}"
                })
        
        result['return_code'] = process.returncode
        
    except subprocess.TimeoutExpired:
        result['errors'].append({
            'type': 'timeout',
            'message': f"Scan timeout after 1800 seconds for {db_path}"
        })
    except FileNotFoundError:
        result['errors'].append({
            'type': 'command_not_found',
            'message': "codeql-cli command not found. Is it installed and in PATH?"
        })
        print("Error: codeql-cli not found in PATH", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        result['errors'].append({
            'type': 'unexpected_error',
            'message': str(e)
        })
    
    return result


def main():
    parser = argparse.ArgumentParser(
        description='Batch scan PyPI packages with CodeQL python-queries qlpack',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p packages.txt -o results.json
  %(prog)s -p packages.txt -o results.json -v
  
Input file formats:
  packages.txt: One package name per line (e.g., 'aiobotocore-2.25.1')
  Databases expected at: databases/{package}-db
        """
    )
    
    parser.add_argument(
        '-p', '--packages',
        type=Path,
        required=True,
        help='File containing newline-delimited package names to scan'
    )
    
    parser.add_argument(
        '-q', '--qlpack-root',
        type=Path,
        default=Path('../codeql/python/ql/src'),
        help='Root directory containing the qlpack (parent of qlpack.yml)'
    )
    
    parser.add_argument(
        '-d', '--database-dir',
        type=Path,
        default=Path('databases'),
        help='Directory containing CodeQL databases'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=Path,
        required=True,
        help='Output JSON file path for cumulative results'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Print verbose output'
    )
    
    parser.add_argument(
        '--indent',
        type=int,
        default=2,
        help='JSON indentation level (default: 2)'
    )
    
    args = parser.parse_args()
    
    # Read input files
    package_names = read_file_lines(args.packages)
    
    if not package_names:
        print("Error: No package names found in input file", file=sys.stderr)
        sys.exit(1)
    
    # Verify qlpack exists
    qlpack_file = args.qlpack_root / 'qlpack.yml'
    if not qlpack_file.exists():
        print(f"Error: qlpack.yml not found at {qlpack_file}", file=sys.stderr)
        sys.exit(1)
    
    # Verify database directory exists
    if not args.database_dir.exists():
        print(f"Error: Database directory not found at {args.database_dir}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(package_names)} packages to scan", file=sys.stderr)
    print(f"CodeQL qlpack: {qlpack_file}", file=sys.stderr)
    print(f"Database directory: {args.database_dir}", file=sys.stderr)
    
    # Create temporary directory for SARIF outputs
    sarif_dir = Path('/tmp') / f'codeql_sarif_{int(time.time())}'
    sarif_dir.mkdir(parents=True, exist_ok=True)
    
    # Run scans
    all_results = {
        'metadata': {
            'total_packages': len(package_names),
            'qlpack_path': str(args.qlpack_root),
            'database_dir': str(args.database_dir),
            'scan_start_time': time.time(),
        },
        'scans': []
    }
    
    for idx, package_name in enumerate(package_names, 1):
        # Construct database path
        db_path = args.database_dir / f'{package_name}-db'
        
        if not db_path.exists():
            print(f"[{idx}/{len(package_names)}] ✗ Database not found: {db_path}", file=sys.stderr)
            all_results['scans'].append({
                'package_name': package_name,
                'package_path': str(db_path),
                'success': False,
                'errors': [{'type': 'database_not_found', 'message': f'Database does not exist at {db_path}'}]
            })
            continue
        
        print(f"[{idx}/{len(package_names)}] Scanning: {package_name}", file=sys.stderr)
        
        # Create SARIF output file
        sarif_output = sarif_dir / f'{package_name}_results.sarif'
        
        scan_result = run_codeql(package_name, str(db_path), args.qlpack_root, sarif_output, args.verbose)
        all_results['scans'].append(scan_result)
        
        if scan_result['success']:
            findings = scan_result['stats']['total_findings']
            print(f"  ✓ Found {findings} findings", file=sys.stderr)
        else:
            print(f"  ✗ Scan failed: {len(scan_result['errors'])} errors", file=sys.stderr)
            if args.verbose and scan_result['errors']:
                for error in scan_result['errors']:
                    print(f"    - {error['type']}: {error['message']}", file=sys.stderr)
    
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
        'failed_scans': len(package_names) - successful_scans,
        'total_findings': total_findings
    }
    
    # Ensure output directory exists
    args.output.parent.mkdir(parents=True, exist_ok=True)
    
    # Write output with proper indentation
    try:
        with open(args.output, 'w') as f:
            json.dump(all_results, f, indent=args.indent, sort_keys=False)
        print(f"\n✓ Results written to: {args.output}", file=sys.stderr)
        print(f"  Successful scans: {successful_scans}/{len(package_names)}", file=sys.stderr)
        print(f"  Total findings: {total_findings}", file=sys.stderr)
        print(f"  Total duration: {all_results['metadata']['total_duration_seconds']:.2f}s", file=sys.stderr)
    except Exception as e:
        print(f"Error writing output file: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Clean up temporary SARIF directory
    try:
        import shutil
        shutil.rmtree(sarif_dir)
    except Exception as e:
        print(f"Warning: Could not clean up temporary directory {sarif_dir}: {e}", file=sys.stderr)


if __name__ == '__main__':
    main()
