(() => {
    const form = document.querySelector('[data-signin-form]');
    const button = form?.querySelector('button[type="submit"]');
    if (!form || !button) return;
    const label = button.textContent;
    form.addEventListener('submit', event => {
        if (button.disabled) {
            event.preventDefault();
            return;
        }
        button.disabled = true;
        button.textContent = 'Signing in…';
        form.setAttribute('aria-busy', 'true');
    });
    // Restore usable controls when Back returns a page from the browser cache.
    window.addEventListener('pageshow', () => {
        button.disabled = false;
        button.textContent = label;
        form.removeAttribute('aria-busy');
    });
})();
