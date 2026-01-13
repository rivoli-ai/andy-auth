# Andy Auth Documentation Maintenance Guide

This document describes the documentation system, maintenance procedures, and quality assurance tools.

## Documentation Overview

### Structure

The documentation consists of **43 HTML pages** organized into the following sections:

```
docs/
├── index.html                 # Overview/Home
├── quickstart.html            # Quick Start Guide
├── installation.html          # Installation Guide
├── configuration.html         # Configuration Reference
├── css/
│   └── docs.css              # Documentation styles
├── js/
│   └── docs.js               # Documentation JavaScript
├── images/
│   └── favicon.png           # Site favicon
├── scripts/
│   ├── review_docs.py        # Basic documentation review
│   └── review_docs_advanced.py # Advanced documentation review
├── admin/                     # Admin Dashboard docs (5 pages)
│   ├── dashboard.html
│   ├── users.html
│   ├── clients.html
│   ├── tokens.html
│   └── audit-logs.html
├── api/                       # API Reference docs (8 pages)
│   ├── endpoints.html
│   ├── authorize.html
│   ├── token.html
│   ├── userinfo.html
│   ├── introspect.html
│   ├── revoke.html
│   ├── register.html
│   └── discovery.html
├── deployment/                # Deployment docs (4 pages)
│   ├── railway.html
│   ├── docker.html
│   ├── production.html
│   └── azure.html
├── mcp/                       # MCP Integration docs (6 pages)
│   ├── overview.html
│   ├── oauth-flow.html
│   ├── claude-desktop.html
│   ├── chatgpt.html
│   ├── vscode-extensions.html
│   └── dcr.html
├── oauth/                     # OAuth & OIDC docs (8 pages)
│   ├── concepts.html
│   ├── authorization-code.html
│   ├── pkce.html
│   ├── client-credentials.html
│   ├── access-tokens.html
│   ├── refresh-tokens.html
│   ├── scopes.html
│   └── claims.html
├── security/                  # Security docs (1 page)
│   └── overview.html
└── tutorials/                 # Language tutorials (7 pages)
    ├── python.html
    ├── csharp.html
    ├── javascript.html
    ├── typescript.html
    ├── java.html
    ├── go.html
    └── rust.html
```

### Key Files

| File | Purpose |
|------|---------|
| `css/docs.css` | All documentation styling including Prism.js syntax highlighting |
| `js/docs.js` | Documentation JavaScript (search, TOC, theme toggle, copy buttons) |
| `images/favicon.png` | Site favicon |

## Running Quality Checks

### Prerequisites

- Python 3.6+
- No additional packages required (uses standard library only)

### Basic Review

Run the basic documentation review to check for common issues:

```bash
cd src/Andy.Auth.Server/wwwroot/docs
python3 scripts/review_docs.py
```

This checks:
- Internal links (broken links to other doc pages)
- Sidebar consistency across all pages
- Prism.js scripts presence
- HTML structure (unclosed tags)
- Code block language classes
- Page navigation links
- Meta tags
- Duplicate IDs
- Port consistency (localhost:7088)

### Advanced Review

Run the advanced review for additional checks:

```bash
cd src/Andy.Auth.Server/wwwroot/docs
python3 scripts/review_docs_advanced.py
```

This additionally checks:
- CSS and JS file existence
- Search modal structure
- External links (target="_blank")
- Title consistency
- Breadcrumbs
- Table of contents
- API endpoint HTTP method badges

### Expected Output

All checks should pass with output similar to:

```
============================================================
COMPREHENSIVE DOCUMENTATION REVIEW
============================================================

Found 43 HTML files to review

=== CHECKING INTERNAL LINKS ===
All internal links are valid!

=== CHECKING SIDEBAR CONSISTENCY ===
All sidebars are consistent!

...

============================================================
SUMMARY
============================================================

All checks passed! Documentation is consistent.
```

## Page Template

All documentation pages follow this structure:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Page Title - Andy Auth Documentation</title>
    <meta name="description" content="Page description">
    <link rel="stylesheet" href="/docs/css/docs.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <link rel="icon" type="image/png" href="/docs/images/favicon.png">
</head>
<body>
    <!-- Header -->
    <header class="docs-header">
        <div class="docs-header-inner">
            <!-- Logo, search, theme toggle, GitHub link -->
        </div>
    </header>

    <!-- Sidebar -->
    <aside class="docs-sidebar">
        <nav>
            <!-- Navigation sections -->
        </nav>
    </aside>

    <!-- Main Content -->
    <main class="docs-main">
        <article class="docs-content">
            <nav class="docs-breadcrumb"><!-- Breadcrumbs --></nav>
            <h1>Page Title</h1>
            <!-- Content -->
            <nav class="docs-page-nav"><!-- Prev/Next navigation --></nav>
        </article>

        <aside class="docs-toc">
            <div class="docs-toc-title">On this page</div>
            <ul class="docs-toc-list"></ul>
        </aside>
    </main>

    <!-- Search Modal -->
    <div class="docs-search-modal" id="search-modal">
        <div class="docs-search-modal-content">
            <input type="text" class="docs-search-modal-input" id="search-modal-input" placeholder="Search documentation...">
            <div class="docs-search-results" id="search-results"></div>
        </div>
    </div>

    <!-- Scripts (MUST be outside search modal) -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <!-- Prism language components -->
    <script src="/docs/js/docs.js"></script>
</body>
</html>
```

## Code Blocks

Use the following structure for code blocks with syntax highlighting:

```html
<div class="code-block">
    <div class="code-block-header">
        <span class="code-block-lang">Language Name</span>
        <button class="code-block-copy">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="9" y="9" width="13" height="13" rx="2"/>
                <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/>
            </svg>
            Copy
        </button>
    </div>
    <pre><code class="language-{lang}">// Code here</code></pre>
</div>
```

### Supported Languages

The following Prism.js language components are loaded:
- `javascript` / `typescript`
- `python`
- `csharp`
- `java`
- `go`
- `rust`
- `bash`
- `json`
- `yaml`
- `docker`
- `http`
- `markup` (HTML)

## Configuration Documentation

When updating configuration documentation, ensure it matches the actual `appsettings.json` structure:

### Correct Section Names

| Documentation | Actual appsettings.json |
|--------------|------------------------|
| OpenIddict settings | `OpenIddict.Server.EncryptionKey/SigningKey` |
| CORS settings | `CorsOrigins.AllowedOrigins` |
| Rate limiting | `IpRateLimiting.GeneralRules` |
| DCR settings | `DynamicClientRegistration.*` |

### Port Numbers

- Development HTTPS: `https://localhost:7088`
- Development HTTP: `http://localhost:5271`
- Docker internal: `http://localhost:5000` (container port)
- Client callback examples: `http://localhost:5000/callback` (client app port)

## Maintenance History

### January 2025

**Documentation Review and Fixes:**

1. **Port Numbers Fixed**
   - Changed `localhost:5001` to `localhost:7088` in quickstart.html and installation.html
   - Changed `localhost:5000` to `localhost:5271` for HTTP port

2. **Configuration Structure Updated** (configuration.html)
   - Updated `OpenIddict` section to show `Server.EncryptionKey/SigningKey` format
   - Changed `Cors` to `CorsOrigins`
   - Changed `RateLimiting` to `IpRateLimiting` with actual endpoint rules
   - Added complete `DynamicClientRegistration` section documentation

3. **Missing Assets Created**
   - Created `/docs/images/favicon.png`

4. **HTML Structure Fixed**
   - Fixed unclosed search modal `</div>` in 31 files
   - Scripts were incorrectly placed inside the search modal div

5. **External Links Fixed**
   - Added `target="_blank"` to external links in quickstart.html and installation.html

6. **Review Scripts Created**
   - `scripts/review_docs.py` - Basic documentation review
   - `scripts/review_docs_advanced.py` - Advanced documentation review

## Adding New Pages

When adding a new documentation page:

1. Copy an existing page as a template
2. Update the `<title>` and meta description
3. Update breadcrumbs
4. Add the page to the sidebar navigation in ALL 43 files
5. Update prev/next navigation links in adjacent pages
6. Run both review scripts to verify consistency

## Common Issues

### Sidebar Out of Sync

If sidebars become inconsistent, use this command to check:

```bash
python3 scripts/review_docs.py | grep -A5 "SIDEBAR"
```

### Missing Prism.js Highlighting

Ensure:
1. Code blocks use `<code class="language-{lang}">` format
2. The language component script is loaded
3. Scripts are placed AFTER the search modal closing `</div>`

### Broken Internal Links

Run the review script and check the "CHECKING INTERNAL LINKS" section.

## Contact

For documentation issues, create an issue at:
https://github.com/rivoli-ai/andy-auth/issues
