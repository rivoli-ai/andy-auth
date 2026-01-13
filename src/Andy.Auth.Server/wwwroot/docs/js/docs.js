// Andy Auth Documentation - Interactive Features

(function() {
    'use strict';

    // Theme Management
    const ThemeManager = {
        init() {
            const saved = localStorage.getItem('docs-theme');
            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            const theme = saved || (prefersDark ? 'dark' : 'light');
            this.setTheme(theme);

            // Listen for system theme changes
            window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
                if (!localStorage.getItem('docs-theme')) {
                    this.setTheme(e.matches ? 'dark' : 'light');
                }
            });
        },

        setTheme(theme) {
            document.documentElement.setAttribute('data-theme', theme);
            localStorage.setItem('docs-theme', theme);
            this.updateToggleIcon(theme);
        },

        toggle() {
            const current = document.documentElement.getAttribute('data-theme');
            this.setTheme(current === 'dark' ? 'light' : 'dark');
        },

        updateToggleIcon(theme) {
            const btn = document.getElementById('theme-toggle');
            if (btn) {
                btn.innerHTML = theme === 'dark'
                    ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
                    : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>';
            }
        }
    };

    // Sidebar Navigation
    const Sidebar = {
        init() {
            // Expand current section
            this.expandCurrentSection();

            // Handle group toggles
            document.querySelectorAll('.docs-sidebar-group-header').forEach(header => {
                header.addEventListener('click', () => {
                    const group = header.closest('.docs-sidebar-group');
                    group.classList.toggle('expanded');
                });
            });

            // Mobile toggle
            const toggle = document.getElementById('sidebar-toggle');
            const sidebar = document.querySelector('.docs-sidebar');
            if (toggle && sidebar) {
                toggle.addEventListener('click', () => {
                    sidebar.classList.toggle('open');
                });

                // Close on outside click
                document.addEventListener('click', (e) => {
                    if (sidebar.classList.contains('open') &&
                        !sidebar.contains(e.target) &&
                        !toggle.contains(e.target)) {
                        sidebar.classList.remove('open');
                    }
                });
            }
        },

        expandCurrentSection() {
            const currentPath = window.location.pathname;
            const activeLink = document.querySelector(`.docs-sidebar-link[href="${currentPath}"]`);
            if (activeLink) {
                activeLink.classList.add('active');
                const group = activeLink.closest('.docs-sidebar-group');
                if (group) {
                    group.classList.add('expanded');
                }
            }
        }
    };

    // Table of Contents
    const TableOfContents = {
        init() {
            const toc = document.querySelector('.docs-toc-list');
            if (!toc) return;

            const headings = document.querySelectorAll('.docs-content h2, .docs-content h3');
            if (headings.length === 0) return;

            // Build TOC
            headings.forEach((heading, index) => {
                if (!heading.id) {
                    heading.id = this.slugify(heading.textContent) + '-' + index;
                }

                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = '#' + heading.id;
                a.className = 'docs-toc-link' + (heading.tagName === 'H3' ? ' toc-h3' : '');
                a.textContent = heading.textContent;
                li.appendChild(a);
                toc.appendChild(li);
            });

            // Intersection observer for active state
            this.observeHeadings(headings);
        },

        slugify(text) {
            return text.toLowerCase()
                .replace(/[^a-z0-9]+/g, '-')
                .replace(/(^-|-$)/g, '');
        },

        observeHeadings(headings) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        document.querySelectorAll('.docs-toc-link').forEach(link => {
                            link.classList.toggle('active', link.getAttribute('href') === '#' + entry.target.id);
                        });
                    }
                });
            }, { rootMargin: '-80px 0px -80% 0px' });

            headings.forEach(heading => observer.observe(heading));
        }
    };

    // Search
    const Search = {
        data: [],
        modal: null,
        input: null,
        results: null,
        selectedIndex: -1,

        init() {
            this.modal = document.getElementById('search-modal');
            this.input = document.getElementById('search-modal-input');
            this.results = document.getElementById('search-results');

            if (!this.modal) return;

            // Load search index
            this.loadIndex();

            // Keyboard shortcuts
            document.addEventListener('keydown', (e) => {
                if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                    e.preventDefault();
                    this.open();
                }
                if (e.key === 'Escape' && this.modal.classList.contains('open')) {
                    this.close();
                }
            });

            // Click to open
            document.querySelectorAll('[data-search-trigger]').forEach(el => {
                el.addEventListener('click', () => this.open());
            });

            // Close on backdrop click
            this.modal.addEventListener('click', (e) => {
                if (e.target === this.modal) this.close();
            });

            // Search input
            if (this.input) {
                this.input.addEventListener('input', () => this.search());
                this.input.addEventListener('keydown', (e) => this.handleKeyNav(e));
            }
        },

        async loadIndex() {
            try {
                const response = await fetch('/docs/search-index.json');
                this.data = await response.json();
            } catch (e) {
                console.warn('Search index not available');
                this.data = [];
            }
        },

        open() {
            this.modal.classList.add('open');
            this.input.focus();
            this.input.select();
            document.body.style.overflow = 'hidden';
        },

        close() {
            this.modal.classList.remove('open');
            this.input.value = '';
            this.results.innerHTML = '';
            this.selectedIndex = -1;
            document.body.style.overflow = '';
        },

        search() {
            const query = this.input.value.toLowerCase().trim();
            if (!query) {
                this.results.innerHTML = '';
                return;
            }

            const matches = this.data.filter(item =>
                item.title.toLowerCase().includes(query) ||
                item.content.toLowerCase().includes(query) ||
                (item.keywords && item.keywords.some(k => k.toLowerCase().includes(query)))
            ).slice(0, 10);

            this.results.innerHTML = matches.map((item, i) => `
                <a href="${item.url}" class="docs-search-result ${i === 0 ? 'selected' : ''}" data-index="${i}">
                    <div class="docs-search-result-title">${this.highlight(item.title, query)}</div>
                    <div class="docs-search-result-path">${item.path}</div>
                </a>
            `).join('') || '<div class="docs-search-result">No results found</div>';

            this.selectedIndex = matches.length > 0 ? 0 : -1;
        },

        highlight(text, query) {
            const regex = new RegExp(`(${query})`, 'gi');
            return text.replace(regex, '<mark>$1</mark>');
        },

        handleKeyNav(e) {
            const results = this.results.querySelectorAll('.docs-search-result[data-index]');
            if (!results.length) return;

            if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.selectedIndex = Math.min(this.selectedIndex + 1, results.length - 1);
                this.updateSelection(results);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.selectedIndex = Math.max(this.selectedIndex - 1, 0);
                this.updateSelection(results);
            } else if (e.key === 'Enter' && this.selectedIndex >= 0) {
                e.preventDefault();
                results[this.selectedIndex].click();
            }
        },

        updateSelection(results) {
            results.forEach((r, i) => r.classList.toggle('selected', i === this.selectedIndex));
        }
    };

    // Code Blocks
    const CodeBlocks = {
        init() {
            document.querySelectorAll('.code-block-copy').forEach(btn => {
                btn.addEventListener('click', () => this.copy(btn));
            });
        },

        async copy(btn) {
            const code = btn.closest('.code-block').querySelector('code').textContent;
            try {
                await navigator.clipboard.writeText(code);
                const originalText = btn.innerHTML;
                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg> Copied!';
                setTimeout(() => btn.innerHTML = originalText, 2000);
            } catch (e) {
                console.error('Failed to copy:', e);
            }
        }
    };

    // Tabs
    const Tabs = {
        init() {
            document.querySelectorAll('.docs-tabs').forEach(tabs => {
                const buttons = tabs.querySelectorAll('.docs-tab-btn');
                const contents = tabs.querySelectorAll('.docs-tab-content');

                buttons.forEach(btn => {
                    btn.addEventListener('click', () => {
                        const target = btn.dataset.tab;

                        buttons.forEach(b => b.classList.toggle('active', b === btn));
                        contents.forEach(c => c.classList.toggle('active', c.id === target));
                    });
                });
            });
        }
    };

    // Anchor links for headings
    const HeadingAnchors = {
        init() {
            document.querySelectorAll('.docs-content h2, .docs-content h3, .docs-content h4').forEach(heading => {
                if (heading.id) {
                    const anchor = document.createElement('a');
                    anchor.className = 'heading-anchor';
                    anchor.href = '#' + heading.id;
                    anchor.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>';
                    anchor.style.cssText = 'opacity:0;margin-left:0.5rem;color:var(--color-text-muted);transition:opacity 0.2s;';
                    heading.appendChild(anchor);
                    heading.style.cssText = 'display:flex;align-items:center;';
                    heading.addEventListener('mouseenter', () => anchor.style.opacity = '1');
                    heading.addEventListener('mouseleave', () => anchor.style.opacity = '0');
                }
            });
        }
    };

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', () => {
        ThemeManager.init();
        Sidebar.init();
        TableOfContents.init();
        Search.init();
        CodeBlocks.init();
        Tabs.init();
        HeadingAnchors.init();
    });

    // Expose theme toggle globally
    window.toggleTheme = () => ThemeManager.toggle();
})();
