#!/usr/bin/env python3
"""
Minimal Java Package Profiler - Extract Java package metadata.

Purpose: Provide raw Java package information for security analysis agents.

Output schema:
{
  "metadata": { ... },       # From pom.xml / build.gradle
  "metadata_source": "...",  # "pom.xml" | "build.gradle" | "build.gradle.kts"
  "files": [ {"path": "...", "lines": N}, ... ],
  "total_files": N,
  "total_lines": N,
  "imports": [ "java.io", "javax.servlet", ... ]
}
"""

import os
import sys
import re
import json
import argparse


try:
    from lxml import etree as ET
    LXML_AVAILABLE = True
except ImportError:
    import xml.etree.ElementTree as ET
    LXML_AVAILABLE = False


def extract_pom_xml(package_path):
    """
    Extract metadata from pom.xml (Maven project).
    Returns raw dict of project-level fields.
    """
    pom_path = os.path.join(package_path, "pom.xml")
    if not os.path.exists(pom_path):
        return None

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Handle Maven POM namespace
        ns = ''
        if root.tag.startswith('{'):
            ns = root.tag.split('}')[0] + '}'

        metadata = {}

        # Core coordinates
        simple_fields = [
            'groupId', 'artifactId', 'version', 'packaging',
            'name', 'description', 'url', 'inceptionYear'
        ]
        for field in simple_fields:
            elem = root.find(f'{ns}{field}')
            if elem is not None and elem.text:
                metadata[field] = elem.text.strip()

        # If groupId/version not at project level, check parent
        parent = root.find(f'{ns}parent')
        if parent is not None:
            for field in ['groupId', 'version']:
                if field not in metadata:
                    elem = parent.find(f'{ns}{field}')
                    if elem is not None and elem.text:
                        metadata[f'parent_{field}'] = elem.text.strip()
                        if field not in metadata:
                            metadata[field] = elem.text.strip()

        # Dependencies (just names, not full tree)
        deps = []
        deps_elem = root.find(f'{ns}dependencies')
        if deps_elem is not None:
            for dep in deps_elem.findall(f'{ns}dependency'):
                group = dep.find(f'{ns}groupId')
                artifact = dep.find(f'{ns}artifactId')
                version = dep.find(f'{ns}version')
                scope = dep.find(f'{ns}scope')
                if group is not None and artifact is not None:
                    dep_info = {
                        'groupId': group.text.strip() if group.text else '',
                        'artifactId': artifact.text.strip() if artifact.text else ''
                    }
                    if version is not None and version.text:
                        dep_info['version'] = version.text.strip()
                    if scope is not None and scope.text:
                        dep_info['scope'] = scope.text.strip()
                    deps.append(dep_info)
        if deps:
            metadata['dependencies'] = deps

        # Modules (for multi-module projects)
        modules_elem = root.find(f'{ns}modules')
        if modules_elem is not None:
            modules = []
            for mod in modules_elem.findall(f'{ns}module'):
                if mod.text:
                    modules.append(mod.text.strip())
            if modules:
                metadata['modules'] = modules

        # Properties (often contain version vars)
        props_elem = root.find(f'{ns}properties')
        if props_elem is not None:
            props = {}
            for prop in props_elem:
                tag = prop.tag.replace(ns, '')
                if prop.text:
                    props[tag] = prop.text.strip()
            if props:
                metadata['properties'] = props

        return metadata
    except Exception as e:
        print(f"[!] Error reading pom.xml: {e}")
        return None


def extract_build_gradle(package_path):
    """
    Extract metadata from build.gradle or build.gradle.kts (Gradle project).
    Uses regex-based extraction since Gradle files are Groovy/Kotlin scripts.
    Returns raw dict of extracted fields.
    """
    gradle_files = ['build.gradle.kts', 'build.gradle']
    gradle_path = None
    for gf in gradle_files:
        candidate = os.path.join(package_path, gf)
        if os.path.exists(candidate):
            gradle_path = candidate
            break

    if gradle_path is None:
        return None

    try:
        with open(gradle_path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read()

        metadata = {}
        metadata_source = os.path.basename(gradle_path)

        # Extract group and version
        group_match = re.search(r'''group\s*[=:]\s*["']([^"']+)["']''', content)
        if group_match:
            metadata['groupId'] = group_match.group(1)

        version_match = re.search(r'''version\s*[=:]\s*["']([^"']+)["']''', content)
        if version_match:
            metadata['version'] = version_match.group(1)

        # Extract dependencies
        deps = []
        # implementation 'group:artifact:version'
        dep_pattern = re.compile(
            r'''(?:implementation|compile|api|testImplementation|compileOnly)\s*\(?["']([^"']+)["']\)?'''
        )
        for match in dep_pattern.finditer(content):
            parts = match.group(1).split(':')
            if len(parts) >= 2:
                dep_info = {'groupId': parts[0], 'artifactId': parts[1]}
                if len(parts) >= 3:
                    dep_info['version'] = parts[2]
                deps.append(dep_info)
        if deps:
            metadata['dependencies'] = deps

        # Extract plugins
        plugins = []
        plugin_pattern = re.compile(r'''id\s*\(?["']([^"']+)["']\)?''')
        for match in plugin_pattern.finditer(content):
            plugins.append(match.group(1))
        if plugins:
            metadata['plugins'] = plugins

        # Extract sourceCompatibility / java version
        java_ver = re.search(
            r'''(?:sourceCompatibility|targetCompatibility|java\.toolchain\.languageVersion)\s*[=:.]\s*["']?([^"'\s\n)]+)''',
            content
        )
        if java_ver:
            metadata['java_version'] = java_ver.group(1)

        return metadata
    except Exception as e:
        print(f"[!] Error reading {os.path.basename(gradle_path)}: {e}")
        return None


def count_java_lines(filepath):
    """Count non-empty, non-comment lines in a Java file."""
    try:
        with open(filepath, "r", encoding='utf-8', errors='ignore') as f:
            lines = 0
            in_block_comment = False
            for line in f:
                stripped = line.strip()

                # Handle block comments
                if in_block_comment:
                    if '*/' in stripped:
                        in_block_comment = False
                    continue

                if stripped.startswith('/*'):
                    if '*/' not in stripped:
                        in_block_comment = True
                    continue

                # Skip empty lines and single-line comments
                if stripped and not stripped.startswith('//'):
                    lines += 1
            return lines
    except Exception:
        return 0


def extract_imports_from_java_file(filepath):
    """Extract all import statements from a Java file."""
    imports = set()
    try:
        with open(filepath, "r", encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip()
                # Match: import [static] package.name.Class;
                match = re.match(r'^import\s+(?:static\s+)?([a-zA-Z_][\w.]*)\s*;', stripped)
                if match:
                    full_import = match.group(1)
                    # Get top two levels for meaningful grouping
                    # e.g., "java.io" from "java.io.File"
                    parts = full_import.split('.')
                    if len(parts) >= 2:
                        imports.add(f"{parts[0]}.{parts[1]}")
                    else:
                        imports.add(parts[0])
                # Stop scanning after class declaration (imports must come before)
                if re.match(r'^(?:public\s+|abstract\s+|final\s+)*(?:class|interface|enum)\s+', stripped):
                    break
    except Exception:
        pass
    return imports


def scan_java_files(package_path, exclude_tests=True):
    """
    Scan package directory for Java/Kotlin files.
    Returns: (file_paths, total_lines, unique_imports)
    """
    test_patterns = {
        'test', 'tests', 'testing', 'testcases',
        'example', 'examples', 'sample', 'samples',
        'demo', 'demos', 'doc', 'docs',
        'benchmark', 'benchmarks', 'it',  # 'it' = integration tests
    }

    exclude_dirs = {
        '.git', '.svn', '.hg', '.gradle', '.mvn',
        'build', 'target', 'out', 'bin',
        'node_modules', '__pycache__',
        '.idea', '.settings', '.vscode',
    }

    java_extensions = {'.java', '.kt', '.kts'}

    files = []
    total_lines = 0
    all_imports = set()

    package_path = os.path.abspath(package_path)

    for root, dirs, filenames in os.walk(package_path):
        # Exclude build/IDE directories
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        # Skip test directories if requested
        if exclude_tests:
            dirs[:] = [d for d in dirs if d.lower() not in test_patterns]

        for filename in filenames:
            ext = os.path.splitext(filename)[1].lower()
            if ext not in java_extensions:
                continue

            filepath = os.path.join(root, filename)
            relpath = os.path.relpath(filepath, package_path)

            # Skip test files if requested
            if exclude_tests:
                relpath_lower = relpath.lower()
                filename_lower = filename.lower()
                # Common Java test patterns
                if any(p in relpath_lower for p in ['src/test/', 'src\\test\\']):
                    continue
                if filename_lower.startswith('test') or filename_lower.endswith('test.java'):
                    continue
                if filename_lower.endswith('tests.java') or filename_lower.endswith('testcase.java'):
                    continue
                # Check if any individual path component exactly matches a test pattern
                # (avoid substring matching, e.g. 'it' must not match 'retrofit')
                relpath_parts = set(relpath_lower.replace('\\', '/').split('/'))
                if relpath_parts & test_patterns:
                    continue

            lines = count_java_lines(filepath)

            if ext == '.java':
                imports = extract_imports_from_java_file(filepath)
                all_imports.update(imports)

            files.append({
                'path': relpath,
                'lines': lines
            })
            total_lines += lines

    return files, total_lines, sorted(list(all_imports))


def find_java_package_root(start_path):
    """
    Find the actual Java package root by looking for build files.
    Handles nested directory structures.
    """
    start_path = os.path.abspath(start_path)

    build_files = ['pom.xml', 'build.gradle', 'build.gradle.kts']

    for bf in build_files:
        if os.path.exists(os.path.join(start_path, bf)):
            return start_path

    # Check one level down
    for entry in os.listdir(start_path):
        subdir = os.path.join(start_path, entry)
        if os.path.isdir(subdir):
            for bf in build_files:
                if os.path.exists(os.path.join(subdir, bf)):
                    print(f"[*] Detected nested structure, using: {subdir}")
                    return subdir

    return start_path


def detect_build_system(package_path):
    """Detect the build system: maven, gradle, or unknown."""
    if os.path.exists(os.path.join(package_path, "pom.xml")):
        return "maven"
    if os.path.exists(os.path.join(package_path, "build.gradle")) or \
       os.path.exists(os.path.join(package_path, "build.gradle.kts")):
        return "gradle"
    return "unknown"


def profile_java_package(package_path, exclude_tests=True, exclude_fields=None):
    """
    Profile a Java package — extract raw metadata without interpretation.
    Output schema matches the Python profiler exactly.

    Args:
        package_path: Path to Java project directory
        exclude_tests: Whether to exclude test files
        exclude_fields: List of field patterns to exclude from metadata

    Returns dict with:
    - metadata: Raw fields from pom.xml or build.gradle
    - metadata_source: Which build file was used
    - files: List of {path, lines} dicts
    - total_files: Count of Java/Kotlin files
    - total_lines: Sum of non-empty, non-comment lines
    - imports: Sorted list of unique top-level package imports (e.g., "java.io")
    """
    print(f"[*] Profiling Java package: {package_path}")

    package_root = find_java_package_root(package_path)
    build_system = detect_build_system(package_root)

    metadata = None
    metadata_source = None

    # Try Maven first, then Gradle
    if build_system == "maven":
        metadata = extract_pom_xml(package_root)
        if metadata is not None:
            metadata_source = "pom.xml"
            print(f"[+] Found metadata in pom.xml")
    elif build_system in ("gradle",):
        metadata = extract_build_gradle(package_root)
        if metadata is not None:
            gradle_files = ['build.gradle.kts', 'build.gradle']
            for gf in gradle_files:
                if os.path.exists(os.path.join(package_root, gf)):
                    metadata_source = gf
                    break
            print(f"[+] Found metadata in {metadata_source}")

    # Fallback: try both
    if metadata is None:
        metadata = extract_pom_xml(package_root)
        if metadata is not None:
            metadata_source = "pom.xml"
        else:
            metadata = extract_build_gradle(package_root)
            if metadata is not None:
                metadata_source = "build.gradle"

    if metadata is None:
        print(f"[!] No metadata found in pom.xml or build.gradle")
        metadata = {}

    # Filter metadata if patterns specified
    if exclude_fields:
        import fnmatch
        original_count = len(metadata)
        filtered = {}
        for key, value in metadata.items():
            excluded = any(fnmatch.fnmatch(key.lower(), p.lower()) for p in exclude_fields)
            if not excluded:
                filtered[key] = value
        excluded_count = original_count - len(filtered)
        if excluded_count > 0:
            print(f"[*] Excluded {excluded_count} metadata field(s)")
        metadata = filtered

    # Scan Java/Kotlin files
    files, total_lines, imports = scan_java_files(package_root, exclude_tests)

    print(f"[+] Found {len(files)} Java/Kotlin files ({total_lines} lines)")
    print(f"[+] Found {len(imports)} unique import packages")

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
        description="Minimal Java package profiler"
    )
    parser.add_argument(
        '--path',
        required=True,
        help='Path to Java project directory'
    )
    parser.add_argument(
        '--output',
        help='Output JSON file path (default: stdout)'
    )
    parser.add_argument(
        '--include-tests',
        action='store_true',
        help='Include test files (default: exclude)'
    )
    parser.add_argument(
        '--exclude-fields',
        nargs='+',
        help='Metadata field patterns to exclude (e.g., "url*" "inceptionYear")'
    )
    parser.add_argument(
        '--pretty',
        action='store_true',
        help='Pretty-print JSON output'
    )

    args = parser.parse_args()

    if not os.path.isdir(args.path):
        print(f"[!] Error: {args.path} is not a directory")
        sys.exit(1)

    exclude_fields = args.exclude_fields
    if not exclude_fields:
        exclude_fields = [
            "url*",
            "inceptionYear",
        ]

    profile = profile_java_package(
        args.path,
        exclude_tests=not args.include_tests,
        exclude_fields=exclude_fields
    )

    if args.pretty:
        json_output = json.dumps(profile, indent=2, ensure_ascii=False)
    else:
        json_output = json.dumps(profile, ensure_ascii=False)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_output)
        print(f"[+] Profile written to {args.output}")
    else:
        print("\n" + "=" * 80)
        print(json_output)


if __name__ == '__main__':
    main()
