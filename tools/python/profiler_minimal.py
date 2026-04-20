#!/usr/bin/env python3
"""
Minimal Package Profiler - Extract package metadata without assumptions.

Purpose: Provide raw package information for security analysis agents.
"""

import os
import sys
import ast
import json
import argparse
import configparser


try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # Fallback for older Python
    except ImportError:
        print("[!] Warning: tomllib/tomli not available. Cannot parse pyproject.toml files.")
        tomllib = None


def extract_pyproject_toml(package_path):
    """
    Extract all metadata from pyproject.toml without processing.
    Returns raw dict of all fields found.
    """
    if tomllib is None:
        return None

    toml_path = os.path.join(package_path, "pyproject.toml")
    if not os.path.exists(toml_path):
        return None

    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)

        # Extract project metadata (PEP 621)
        metadata = {}
        if 'project' in data:
            metadata.update(data['project'])

        # Extract Poetry metadata if present
        if 'tool' in data and 'poetry' in data['tool']:
            # Merge poetry fields, prefixing with 'poetry_' to avoid conflicts
            for key, value in data['tool']['poetry'].items():
                metadata[f'poetry_{key}'] = value

        return metadata
    except Exception as e:
        print(f"[!] Error reading pyproject.toml: {e}")
        return None


def extract_setup_py(package_path):
    """
    Extract metadata from setup.py by parsing AST.
    Returns raw dict of all setup() kwargs.
    """
    setup_path = os.path.join(package_path, "setup.py")
    if not os.path.exists(setup_path):
        return None

    try:
        with open(setup_path, "r", encoding='utf-8') as f:
            content = f.read()

        tree = ast.parse(content)

        # First pass: collect module-level variables
        module_vars = {}
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        value = _extract_value(node.value)
                        if value is not None:
                            module_vars[target.id] = value

        # Second pass: find setup() call
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Handle both setup() and setuptools.setup()
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name == "setup":
                    metadata = {}
                    for keyword in node.keywords:
                        key = keyword.arg
                        if key:  # Skip **kwargs
                            value = _extract_value(keyword.value, module_vars)
                            if value is not None:
                                metadata[key] = value
                    if metadata:  # Only return if we found something
                        return metadata

        return None
    except Exception as e:
        print(f"[!] Error parsing setup.py: {e}")
        import traceback
        traceback.print_exc()
        return None


def extract_setup_cfg(package_path):
    """
    Extract metadata from setup.cfg using ConfigParser.
    Returns raw dict of all fields.
    """
    cfg_path = os.path.join(package_path, "setup.cfg")
    if not os.path.exists(cfg_path):
        return None

    try:
        config = configparser.ConfigParser()
        config.read(cfg_path)

        metadata = {}

        # Extract metadata section
        if "metadata" in config:
            for key, value in config["metadata"].items():
                # Handle multiline values (like classifiers)
                if '\n' in value:
                    metadata[key] = [line.strip() for line in value.split('\n') if line.strip()]
                else:
                    metadata[key] = value

        # Extract options section
        if "options" in config:
            for key, value in config["options"].items():
                if '\n' in value:
                    metadata[f'options_{key}'] = [line.strip() for line in value.split('\n') if line.strip()]
                else:
                    metadata[f'options_{key}'] = value

        # Extract project_urls if present
        if "metadata" in config and "project_urls" in config:
            urls = {}
            for key, value in config["project_urls"].items():
                urls[key] = value
            metadata['project_urls'] = urls

        return metadata
    except Exception as e:
        print(f"[!] Error reading setup.cfg: {e}")
        return None


def _extract_value(node, module_vars=None):
    """
    Extract value from AST node - handles strings, lists, dicts, and variable references.
    """
    if module_vars is None:
        module_vars = {}

    # String constant
    if isinstance(node, ast.Constant):
        return node.value
    # Legacy string (Python < 3.8)
    elif hasattr(node, 's'):
        return node.s
    # Variable reference
    elif isinstance(node, ast.Name) and node.id in module_vars:
        return module_vars[node.id]
    # List
    elif isinstance(node, ast.List):
        return [_extract_value(elt, module_vars) for elt in node.elts]
    # Dict
    elif isinstance(node, ast.Dict):
        result = {}
        for key_node, val_node in zip(node.keys, node.values):
            key = _extract_value(key_node, module_vars)
            val = _extract_value(val_node, module_vars)
            if key:
                result[key] = val
        return result
    # Tuple
    elif isinstance(node, ast.Tuple):
        return tuple(_extract_value(elt, module_vars) for elt in node.elts)

    return None


def count_file_lines(filepath):
    """Count non-empty, non-comment lines in a Python file."""
    try:
        with open(filepath, "r", encoding='utf-8', errors='ignore') as f:
            lines = 0
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    lines += 1
            return lines
    except Exception:
        return 0


def extract_imports_from_file(filepath):
    """Extract all import statements from a Python file."""
    try:
        with open(filepath, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()

        tree = ast.parse(content)
        imports = set()

        for node in ast.walk(tree):
            # import foo
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # Get top-level module name
                    module = alias.name.split('.')[0]
                    imports.add(module)
            # from foo import bar
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    # Get top-level module name
                    module = node.module.split('.')[0]
                    imports.add(module)

        return imports
    except Exception:
        return set()


def scan_package_files(package_path, exclude_tests=True):
    """
    Scan package directory for Python files.
    Returns: (file_paths, total_lines, unique_imports)
    """
    test_patterns = {
        'test', 'tests', 'testing',
        'example', 'examples',
        'demo', 'demos',
        'doc', 'docs',
        'benchmark', 'benchmarks',
    }

    files = []
    total_lines = 0
    all_imports = set()

    exclude_dirs = {'.git', '.svn', '.hg', 'venv', '.venv', 'env', '__pycache__',
                    'build', 'dist', '.tox', '.eggs', '*.egg-info'}

    # Normalize package_path to absolute for consistent relative path calculation
    package_path = os.path.abspath(package_path)

    for root, dirs, filenames in os.walk(package_path):
        # Exclude common non-source directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs and not d.endswith('.egg-info')]

        # Skip test directories if requested
        if exclude_tests:
            dirs[:] = [d for d in dirs if d.lower() not in test_patterns]

        for filename in filenames:
            if not filename.endswith('.py'):
                continue

            filepath = os.path.join(root, filename)

            # Get relative path from package root (will be clean, starting from package content)
            relpath = os.path.relpath(filepath, package_path)

            # Skip test files if requested
            if exclude_tests:
                filename_lower = filename.lower()
                relpath_lower = relpath.lower()
                if any(pattern in filename_lower for pattern in test_patterns):
                    continue
                # Also check path components
                if any(pattern in relpath_lower for pattern in test_patterns):
                    continue

            # Count lines
            lines = count_file_lines(filepath)

            # Extract imports
            imports = extract_imports_from_file(filepath)

            files.append({
                'path': relpath,
                'lines': lines
            })

            total_lines += lines
            all_imports.update(imports)

    return files, total_lines, sorted(list(all_imports))


def find_package_root(start_path):
    """
    Find the actual package root by looking for metadata files.
    Handles nested directory structures (e.g., package-1.0/package-1.0/setup.py)

    Returns the path containing metadata files, or the original path if none found.
    """
    start_path = os.path.abspath(start_path)

    # Check if metadata exists at the given path
    metadata_files = ['pyproject.toml', 'setup.py', 'setup.cfg']

    for meta_file in metadata_files:
        if os.path.exists(os.path.join(start_path, meta_file)):
            return start_path

    # Check one level down - common pattern: package-1.0/package-1.0/setup.py
    for entry in os.listdir(start_path):
        subdir = os.path.join(start_path, entry)
        if os.path.isdir(subdir):
            for meta_file in metadata_files:
                if os.path.exists(os.path.join(subdir, meta_file)):
                    print(f"[*] Detected nested structure, using: {subdir}")
                    return subdir

    # No metadata found, return original path
    return start_path


def filter_metadata(metadata, exclude_patterns):
    """
    Filter metadata by excluding fields matching patterns.
    Supports wildcards (e.g., 'author*' matches 'author', 'author_email', 'authors')

    Args:
        metadata: Dict of metadata fields
        exclude_patterns: List of patterns (e.g., ['author*', 'maintainer*'])

    Returns:
        Filtered metadata dict
    """
    if not exclude_patterns:
        return metadata

    import fnmatch

    filtered = {}
    for key, value in metadata.items():
        # Check if key matches any exclude pattern
        excluded = False
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(key.lower(), pattern.lower()):
                excluded = True
                break

        if not excluded:
            filtered[key] = value

    return filtered


def profile_package(package_path, exclude_tests=True, exclude_fields=None):
    """
    Profile a package - extract raw metadata without interpretation.

    Args:
        package_path: Path to package directory
        exclude_tests: Whether to exclude test/example files
        exclude_fields: List of field patterns to exclude from metadata (e.g., ['author*', 'maintainer*'])

    Returns dict with:
    - metadata: Raw fields from pyproject.toml/setup.py/setup.cfg
    - files: List of {path, lines} dicts
    - total_files: Count of Python files
    - total_lines: Sum of non-empty, non-comment lines
    - imports: Sorted list of unique top-level module imports
    """
    print(f"[*] Profiling package: {package_path}")

    # Find the actual package root (handles nested structures)
    package_root = find_package_root(package_path)

    # Try to extract metadata from config files
    metadata = None
    metadata_source = None

    # Priority: pyproject.toml > setup.py > setup.cfg
    metadata = extract_pyproject_toml(package_root)
    if metadata:
        metadata_source = "pyproject.toml"
        print(f"[+] Found metadata in pyproject.toml")

    if not metadata:
        metadata = extract_setup_py(package_root)
        if metadata:
            metadata_source = "setup.py"
            print(f"[+] Found metadata in setup.py")

    if not metadata:
        metadata = extract_setup_cfg(package_root)
        if metadata:
            metadata_source = "setup.cfg"
            print(f"[+] Found metadata in setup.cfg")

    if not metadata:
        print(f"[!] No metadata found in pyproject.toml, setup.py, or setup.cfg")
        metadata = {}

    # Filter metadata if exclude patterns specified
    if exclude_fields:
        original_count = len(metadata)
        metadata = filter_metadata(metadata, exclude_fields)
        excluded_count = original_count - len(metadata)
        if excluded_count > 0:
            print(f"[*] Excluded {excluded_count} metadata field(s) matching patterns: {exclude_fields}")

    # Scan package files using the package root
    files, total_lines, imports = scan_package_files(package_root, exclude_tests)

    print(f"[+] Found {len(files)} Python files ({total_lines} lines)")
    print(f"[+] Found {len(imports)} unique imports")

    # Build profile
    profile = {
        'metadata': metadata,
        'metadata_source': metadata_source,
        'files': files,
        'total_files': len(files),
        'total_lines': total_lines,
        'imports': imports
    }

    return profile


def main():
    parser = argparse.ArgumentParser(
        description="Minimal package profiler"
    )
    parser.add_argument(
        '--path',
        required=True,
        help='Path to package directory'
    )
    parser.add_argument(
        '--output',
        help='Output JSON file path (default: stdout)'
    )
    parser.add_argument(
        '--include-tests',
        action='store_true',
        help='Include test/example files (default: exclude)'
    )
    parser.add_argument(
        '--exclude-fields',
        nargs='+',
        help='Metadata field patterns to exclude (supports wildcards, e.g., "author*" "maintainer*")'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty-print JSON output'
    )

    args = parser.parse_args()

    # Validate path
    if not os.path.isdir(args.path):
        print(f"[!] Error: {args.path} is not a directory")
        sys.exit(1)

    exclude_fields = args.exclude_fields
    if not exclude_fields:
        exclude_fields = [
            "author*",
            "maintainer*",
            "contact*",
            "url*",
            "download*"
        ]

    # Profile package
    profile = profile_package(
        args.path,
        exclude_tests=not args.include_tests,
        exclude_fields=exclude_fields
    )

    # Output
    if args.pretty:
        json_output = json.dumps(profile, indent=2, ensure_ascii=False)
    else:
        json_output = json.dumps(profile, ensure_ascii=False)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_output)
        print(f"[+] Profile written to {args.output}")
    else:
        print("\n" + "="*80)
        print(json_output)


if __name__ == '__main__':
    main()
