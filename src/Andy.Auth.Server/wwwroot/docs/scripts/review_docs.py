#!/usr/bin/env python3
"""
Comprehensive Documentation Review Script

This script performs basic quality checks on all Andy Auth documentation pages.

Usage:
    cd src/Andy.Auth.Server/wwwroot/docs
    python3 scripts/review_docs.py

Checks performed:
    - Internal links (broken links to other doc pages)
    - Sidebar consistency across all pages
    - Prism.js scripts presence
    - HTML structure (unclosed tags)
    - Code block language classes
    - Page navigation links (prev/next)
    - Meta tags (title, description, viewport)
    - Duplicate IDs within pages
    - Port consistency (should use localhost:7088)
"""
import os
import re
from pathlib import Path
from collections import defaultdict

# Get the docs directory relative to this script
SCRIPT_DIR = Path(__file__).parent
DOCS_DIR = SCRIPT_DIR.parent


def get_all_html_files():
    """Get all HTML files in the docs directory."""
    return sorted(DOCS_DIR.rglob("*.html"))


def check_internal_links(files):
    """Check for broken internal links."""
    print("\n=== CHECKING INTERNAL LINKS ===")
    broken = []
    link_pattern = re.compile(r'href="(/docs/[^"#]+)"')

    for f in files:
        content = f.read_text()
        links = link_pattern.findall(content)
        for link in links:
            # Convert /docs/... to actual file path
            target_path = DOCS_DIR / link.replace("/docs/", "")
            if not target_path.exists():
                broken.append((f.relative_to(DOCS_DIR), link))

    if broken:
        print("BROKEN LINKS FOUND:")
        for src, link in broken:
            print(f"  {src} -> {link}")
    else:
        print("All internal links are valid!")
    return broken


def check_sidebar_consistency(files):
    """Check that all files have the same sidebar."""
    print("\n=== CHECKING SIDEBAR CONSISTENCY ===")
    sidebar_pattern = re.compile(r'<aside class="docs-sidebar">(.*?)</aside>', re.DOTALL)

    sidebars = {}
    for f in files:
        content = f.read_text()
        match = sidebar_pattern.search(content)
        if match:
            # Normalize whitespace for comparison
            sidebar = re.sub(r'\s+', ' ', match.group(1).strip())
            # Remove 'active' class for comparison
            sidebar = re.sub(r' class="docs-sidebar-link active"', ' class="docs-sidebar-link"', sidebar)
            sidebars[f.relative_to(DOCS_DIR)] = sidebar
        else:
            print(f"  MISSING SIDEBAR: {f.relative_to(DOCS_DIR)}")

    # Compare all sidebars to the first one
    if sidebars:
        reference_file = list(sidebars.keys())[0]
        reference_sidebar = sidebars[reference_file]
        different = []
        for f, sidebar in sidebars.items():
            if sidebar != reference_sidebar:
                different.append(f)

        if different:
            print(f"SIDEBAR DIFFERS from {reference_file}:")
            for f in different:
                print(f"  {f}")
        else:
            print("All sidebars are consistent!")
    return sidebars


def check_prism_scripts(files):
    """Check that all files have Prism.js scripts."""
    print("\n=== CHECKING PRISM.JS SCRIPTS ===")
    missing = []
    for f in files:
        content = f.read_text()
        if 'prism.min.js' not in content:
            missing.append(f.relative_to(DOCS_DIR))

    if missing:
        print("MISSING PRISM.JS:")
        for f in missing:
            print(f"  {f}")
    else:
        print("All files have Prism.js scripts!")
    return missing


def check_html_structure(files):
    """Check for common HTML structure issues."""
    print("\n=== CHECKING HTML STRUCTURE ===")
    issues = []

    for f in files:
        content = f.read_text()
        file_issues = []

        # Check for missing closing tags
        if content.count('<main') != content.count('</main>'):
            file_issues.append("Unclosed <main> tag")

        if content.count('<article') != content.count('</article>'):
            file_issues.append("Unclosed <article> tag")

        if content.count('<aside') != content.count('</aside>'):
            file_issues.append("Unclosed <aside> tag")

        # Check for header structure
        if 'docs-header-inner' not in content:
            file_issues.append("Missing docs-header-inner class")

        if file_issues:
            issues.append((f.relative_to(DOCS_DIR), file_issues))

    if issues:
        print("HTML STRUCTURE ISSUES:")
        for f, file_issues in issues:
            print(f"  {f}:")
            for issue in file_issues:
                print(f"    - {issue}")
    else:
        print("No major HTML structure issues found!")
    return issues


def check_code_blocks(files):
    """Check that code blocks have proper language classes."""
    print("\n=== CHECKING CODE BLOCKS ===")
    code_pattern = re.compile(r'<code class="([^"]*)"')
    issues = []

    for f in files:
        content = f.read_text()
        file_issues = []

        # Check for code blocks without language class
        if '<code>' in content and '<pre>' in content:
            # Has code in pre without language class
            if re.search(r'<pre><code>', content):
                file_issues.append("Code block without language class")

        # Check for empty language classes
        matches = code_pattern.findall(content)
        for match in matches:
            if not match or match == '':
                file_issues.append("Empty language class")

        if file_issues:
            issues.append((f.relative_to(DOCS_DIR), file_issues))

    if issues:
        print("CODE BLOCK ISSUES:")
        for f, file_issues in issues:
            print(f"  {f}:")
            for issue in file_issues:
                print(f"    - {issue}")
    else:
        print("All code blocks have proper language classes!")
    return issues


def check_page_navigation(files):
    """Check that prev/next navigation links are valid."""
    print("\n=== CHECKING PAGE NAVIGATION ===")
    nav_pattern = re.compile(r'<a href="([^"]+)" class="docs-page-nav-link (prev|next)"')
    issues = []

    for f in files:
        content = f.read_text()
        matches = nav_pattern.findall(content)
        for link, direction in matches:
            if link.startswith('/docs/'):
                target_path = DOCS_DIR / link.replace("/docs/", "")
                if not target_path.exists():
                    issues.append((f.relative_to(DOCS_DIR), f"{direction}: {link}"))

    if issues:
        print("BROKEN NAVIGATION LINKS:")
        for f, issue in issues:
            print(f"  {f}: {issue}")
    else:
        print("All navigation links are valid!")
    return issues


def check_meta_tags(files):
    """Check that all files have proper meta tags."""
    print("\n=== CHECKING META TAGS ===")
    issues = []

    for f in files:
        content = f.read_text()
        file_issues = []

        if '<title>' not in content:
            file_issues.append("Missing <title> tag")

        if 'meta name="description"' not in content:
            file_issues.append("Missing meta description")

        if 'meta name="viewport"' not in content:
            file_issues.append("Missing viewport meta tag")

        if file_issues:
            issues.append((f.relative_to(DOCS_DIR), file_issues))

    if issues:
        print("META TAG ISSUES:")
        for f, file_issues in issues:
            print(f"  {f}:")
            for issue in file_issues:
                print(f"    - {issue}")
    else:
        print("All files have proper meta tags!")
    return issues


def check_duplicate_ids(files):
    """Check for duplicate IDs within each file."""
    print("\n=== CHECKING FOR DUPLICATE IDS ===")
    id_pattern = re.compile(r'id="([^"]+)"')
    issues = []

    for f in files:
        content = f.read_text()
        ids = id_pattern.findall(content)
        duplicates = [id for id in ids if ids.count(id) > 1]
        if duplicates:
            issues.append((f.relative_to(DOCS_DIR), list(set(duplicates))))

    if issues:
        print("DUPLICATE IDS:")
        for f, dups in issues:
            print(f"  {f}: {', '.join(dups)}")
    else:
        print("No duplicate IDs found!")
    return issues


def check_port_consistency(files):
    """Check for consistent port usage."""
    print("\n=== CHECKING PORT CONSISTENCY ===")
    issues = []

    for f in files:
        content = f.read_text()

        # Check for old port 5001 (should be 7088 for Andy Auth server)
        if 'localhost:5001' in content:
            issues.append((f.relative_to(DOCS_DIR), "Contains localhost:5001 (should be 7088)"))

    if issues:
        print("PORT ISSUES:")
        for f, issue in issues:
            print(f"  {f}: {issue}")
    else:
        print("No port inconsistencies found!")
    return issues


def main():
    print("=" * 60)
    print("COMPREHENSIVE DOCUMENTATION REVIEW")
    print("=" * 60)

    files = get_all_html_files()
    print(f"\nFound {len(files)} HTML files to review")

    all_issues = {}

    all_issues['internal_links'] = check_internal_links(files)
    all_issues['sidebar'] = check_sidebar_consistency(files)
    all_issues['prism'] = check_prism_scripts(files)
    all_issues['html_structure'] = check_html_structure(files)
    all_issues['code_blocks'] = check_code_blocks(files)
    all_issues['navigation'] = check_page_navigation(files)
    all_issues['meta_tags'] = check_meta_tags(files)
    all_issues['duplicate_ids'] = check_duplicate_ids(files)
    all_issues['ports'] = check_port_consistency(files)

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    total_issues = sum(len(v) if isinstance(v, list) else 0 for v in all_issues.values())
    if total_issues == 0:
        print("\nAll checks passed! Documentation is consistent.")
    else:
        print(f"\nTotal issues found: {total_issues}")

    return total_issues


if __name__ == "__main__":
    exit(main())
