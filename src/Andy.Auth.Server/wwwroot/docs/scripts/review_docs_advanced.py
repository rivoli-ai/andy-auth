#!/usr/bin/env python3
"""
Advanced Documentation Review Script

This script performs additional quality checks beyond the basic review.

Usage:
    cd src/Andy.Auth.Server/wwwroot/docs
    python3 scripts/review_docs_advanced.py

Additional checks:
    - CSS and JS file existence
    - Search modal structure (proper closing)
    - External links (target="_blank")
    - Title format consistency
    - Breadcrumbs presence
    - Table of contents section
    - API endpoint HTTP method badges
"""
import os
import re
from pathlib import Path

# Get the docs directory relative to this script
SCRIPT_DIR = Path(__file__).parent
DOCS_DIR = SCRIPT_DIR.parent


def get_all_html_files():
    return sorted(DOCS_DIR.rglob("*.html"))


def check_search_modal_structure(files):
    """Check that search modal is properly closed before scripts."""
    print("\n=== CHECKING SEARCH MODAL STRUCTURE ===")
    issues = []

    for f in files:
        content = f.read_text()

        # The proper structure should have </div> closing the search modal before scripts
        if 'docs-search-modal' in content:
            # Find the search modal
            modal_start = content.find('<div class="docs-search-modal"')
            if modal_start == -1:
                modal_start = content.find("<div class='docs-search-modal'")

            if modal_start != -1:
                # Find first <script after modal
                script_start = content.find('<script', modal_start)

                if script_start != -1:
                    between = content[modal_start:script_start]

                    # Count divs - should be properly balanced
                    open_divs = between.count('<div')
                    close_divs = between.count('</div>')

                    if open_divs != close_divs:
                        issues.append((f.relative_to(DOCS_DIR),
                            f"Unbalanced divs in search modal section: {open_divs} open, {close_divs} close"))

    if issues:
        print("SEARCH MODAL STRUCTURE ISSUES:")
        for f, issue in issues:
            print(f"  {f}: {issue}")
    else:
        print("All search modals have correct structure!")
    return issues


def check_external_links(files):
    """Check that external links have target='_blank'."""
    print("\n=== CHECKING EXTERNAL LINKS ===")
    issues = []

    external_pattern = re.compile(r'<a\s+([^>]*href="https?://[^"]*"[^>]*)>', re.IGNORECASE)

    for f in files:
        content = f.read_text()
        matches = external_pattern.findall(content)

        for match in matches:
            if 'target="_blank"' not in match and "target='_blank'" not in match:
                # Extract the href
                href_match = re.search(r'href="([^"]+)"', match)
                if href_match:
                    href = href_match.group(1)
                    # Skip localhost links
                    if 'localhost' not in href:
                        issues.append((f.relative_to(DOCS_DIR), f"Missing target=_blank: {href[:50]}..."))

    if issues:
        print("EXTERNAL LINK ISSUES (missing target=_blank):")
        for f, issue in issues[:10]:  # Show first 10
            print(f"  {f}: {issue}")
        if len(issues) > 10:
            print(f"  ... and {len(issues) - 10} more")
    else:
        print("All external links are properly configured!")
    return issues


def check_css_file_exists():
    """Check that CSS file exists and is referenced correctly."""
    print("\n=== CHECKING CSS FILE ===")
    css_path = DOCS_DIR / "css" / "docs.css"

    if css_path.exists():
        print(f"CSS file exists: {css_path}")
        return True
    else:
        print(f"CSS FILE MISSING: {css_path}")
        return False


def check_js_file_exists():
    """Check that JS file exists and is referenced correctly."""
    print("\n=== CHECKING JS FILE ===")
    js_path = DOCS_DIR / "js" / "docs.js"

    if js_path.exists():
        print(f"JS file exists: {js_path}")
        return True
    else:
        print(f"JS FILE MISSING: {js_path}")
        return False


def check_consistent_titles(files):
    """Check that all pages have consistent title format."""
    print("\n=== CHECKING TITLE CONSISTENCY ===")
    title_pattern = re.compile(r'<title>([^<]+)</title>')
    issues = []

    for f in files:
        content = f.read_text()
        match = title_pattern.search(content)

        if match:
            title = match.group(1)
            if '- Andy Auth Documentation' not in title and 'Andy Auth Documentation' not in title:
                issues.append((f.relative_to(DOCS_DIR), f"Title doesn't follow pattern: {title}"))
        else:
            issues.append((f.relative_to(DOCS_DIR), "Missing title"))

    if issues:
        print("TITLE ISSUES:")
        for f, issue in issues:
            print(f"  {f}: {issue}")
    else:
        print("All titles follow consistent pattern!")
    return issues


def check_breadcrumbs(files):
    """Check that all pages have breadcrumbs."""
    print("\n=== CHECKING BREADCRUMBS ===")
    issues = []

    for f in files:
        content = f.read_text()

        if 'docs-breadcrumb' not in content:
            issues.append(f.relative_to(DOCS_DIR))

    if issues:
        print("MISSING BREADCRUMBS:")
        for f in issues:
            print(f"  {f}")
    else:
        print("All pages have breadcrumbs!")
    return issues


def check_toc_section(files):
    """Check that all pages have table of contents section."""
    print("\n=== CHECKING TABLE OF CONTENTS ===")
    issues = []

    for f in files:
        content = f.read_text()

        if 'docs-toc' not in content:
            issues.append(f.relative_to(DOCS_DIR))

    if issues:
        print("MISSING TABLE OF CONTENTS:")
        for f in issues:
            print(f"  {f}")
    else:
        print("All pages have table of contents section!")
    return issues


def check_endpoint_http_methods(files):
    """Check that API endpoint docs have proper HTTP method badges."""
    print("\n=== CHECKING API ENDPOINT DOCUMENTATION ===")
    api_files = [f for f in files if '/api/' in str(f)]
    issues = []

    for f in api_files:
        content = f.read_text()

        # API pages should have at least one HTTP method
        if 'endpoint-method' not in content:
            issues.append((f.relative_to(DOCS_DIR), "Missing HTTP method badges"))

    if issues:
        print("API DOCUMENTATION ISSUES:")
        for f, issue in issues:
            print(f"  {f}: {issue}")
    else:
        print("All API pages have proper HTTP method badges!")
    return issues


def check_favicon_exists():
    """Check that favicon exists."""
    print("\n=== CHECKING FAVICON ===")
    favicon_path = DOCS_DIR / "images" / "favicon.png"

    if favicon_path.exists():
        print(f"Favicon exists: {favicon_path}")
        return True
    else:
        print(f"FAVICON MISSING: {favicon_path}")
        return False


def main():
    print("=" * 60)
    print("ADVANCED DOCUMENTATION REVIEW")
    print("=" * 60)

    files = get_all_html_files()
    print(f"\nFound {len(files)} HTML files to review")

    all_issues = []

    css_ok = check_css_file_exists()
    js_ok = check_js_file_exists()
    favicon_ok = check_favicon_exists()

    if not css_ok:
        all_issues.append("CSS file missing")
    if not js_ok:
        all_issues.append("JS file missing")
    if not favicon_ok:
        all_issues.append("Favicon missing")

    issues = check_search_modal_structure(files)
    all_issues.extend(issues)

    issues = check_external_links(files)
    all_issues.extend(issues)

    issues = check_consistent_titles(files)
    all_issues.extend(issues)

    issues = check_breadcrumbs(files)
    # Note: index.html not having breadcrumbs is expected
    filtered_issues = [i for i in issues if str(i) != 'index.html']
    all_issues.extend(filtered_issues)

    issues = check_toc_section(files)
    all_issues.extend(issues)

    issues = check_endpoint_http_methods(files)
    all_issues.extend(issues)

    print("\n" + "=" * 60)
    print("ADVANCED REVIEW COMPLETE")
    print("=" * 60)

    if not all_issues:
        print("\nAll advanced checks passed!")
    else:
        print(f"\nIssues found: {len(all_issues)}")

    return len(all_issues)


if __name__ == "__main__":
    exit(main())
