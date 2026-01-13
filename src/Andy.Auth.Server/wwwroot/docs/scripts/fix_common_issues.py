#!/usr/bin/env python3
"""
Fix Common Documentation Issues

This script can automatically fix common issues found during documentation review.

Usage:
    cd src/Andy.Auth.Server/wwwroot/docs
    python3 scripts/fix_common_issues.py [--dry-run]

Options:
    --dry-run    Show what would be fixed without making changes

Fixes available:
    - Search modal structure (missing closing </div>)
    - External links (add target="_blank")
    - Port numbers (5001 -> 7088)
"""
import os
import re
import sys
from pathlib import Path

# Get the docs directory relative to this script
SCRIPT_DIR = Path(__file__).parent
DOCS_DIR = SCRIPT_DIR.parent

DRY_RUN = '--dry-run' in sys.argv


def get_all_html_files():
    return sorted(DOCS_DIR.rglob("*.html"))


def fix_search_modal(file_path):
    """Fix the search modal structure by adding missing closing div."""
    content = file_path.read_text()
    original = content

    # Pattern: search-results div followed directly by scripts (missing closing div for search-modal)
    pattern = r'(<div class="docs-search-results" id="search-results"></div>\s*</div>)\s*(<script)'

    if re.search(pattern, content):
        # Add closing </div> for the search-modal before scripts
        new_content = re.sub(
            pattern,
            r'\1\n    </div>\n\n    \2',
            content
        )

        if new_content != original:
            if not DRY_RUN:
                file_path.write_text(new_content)
            return True

    return False


def fix_external_links(file_path):
    """Add target="_blank" to external links that don't have it."""
    content = file_path.read_text()
    original = content

    # Pattern: external links without target="_blank"
    # Matches <a href="https://..." but NOT if it already has target=
    pattern = r'(<a\s+)(?!([^>]*target=))([^>]*href="https?://(?!localhost)[^"]*"[^>]*>)'

    def add_target(match):
        return match.group(1) + match.group(3).replace('>', ' target="_blank">')

    new_content = re.sub(pattern, add_target, content)

    if new_content != original:
        if not DRY_RUN:
            file_path.write_text(new_content)
        return True

    return False


def fix_port_numbers(file_path):
    """Fix port 5001 to 7088."""
    content = file_path.read_text()
    original = content

    # Replace localhost:5001 with localhost:7088
    new_content = content.replace('localhost:5001', 'localhost:7088')

    if new_content != original:
        if not DRY_RUN:
            file_path.write_text(new_content)
        return True

    return False


def main():
    if DRY_RUN:
        print("=" * 60)
        print("DRY RUN - No changes will be made")
        print("=" * 60)
    else:
        print("=" * 60)
        print("FIXING COMMON DOCUMENTATION ISSUES")
        print("=" * 60)

    files = get_all_html_files()
    print(f"\nProcessing {len(files)} HTML files\n")

    # Track fixes
    fixes = {
        'search_modal': [],
        'external_links': [],
        'port_numbers': []
    }

    for f in files:
        rel_path = f.relative_to(DOCS_DIR)

        if fix_search_modal(f):
            fixes['search_modal'].append(rel_path)
            print(f"{'Would fix' if DRY_RUN else 'Fixed'} search modal: {rel_path}")

        if fix_external_links(f):
            fixes['external_links'].append(rel_path)
            print(f"{'Would fix' if DRY_RUN else 'Fixed'} external links: {rel_path}")

        if fix_port_numbers(f):
            fixes['port_numbers'].append(rel_path)
            print(f"{'Would fix' if DRY_RUN else 'Fixed'} port numbers: {rel_path}")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)

    total = sum(len(v) for v in fixes.values())
    if total == 0:
        print("\nNo issues found to fix!")
    else:
        print(f"\nSearch modal fixes: {len(fixes['search_modal'])}")
        print(f"External link fixes: {len(fixes['external_links'])}")
        print(f"Port number fixes: {len(fixes['port_numbers'])}")
        print(f"\nTotal files {'that would be' if DRY_RUN else ''} modified: {total}")

    return 0


if __name__ == "__main__":
    exit(main())
