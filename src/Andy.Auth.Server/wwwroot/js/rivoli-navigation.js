// Keep keyboard behavior attached when Blazor replaces prerendered navigation.
(() => {
  let open = false;
  const sync = () => {
    const sidebar = document.getElementById('sidebar');
    const main = document.querySelector('.main-wrapper');
    if (!sidebar || !main) return;
    const next = innerWidth <= 768 && sidebar.classList.contains('open');
    main.inert = next;
    sidebar.inert = innerWidth <= 768 && !next;
    const trigger = document.querySelector('.mobile-menu-btn');
    trigger?.setAttribute('aria-expanded', String(next));
    if (next) { sidebar.setAttribute('role', 'dialog'); sidebar.setAttribute('aria-modal', 'true'); }
    else { sidebar.removeAttribute('role'); sidebar.removeAttribute('aria-modal'); }
    if (next && !open) sidebar.querySelector('.native-drawer-close')?.focus();
    if (!next && open) trigger?.focus();
    open = next;
  };
  new MutationObserver(sync).observe(document.body, { childList:true, subtree:true, attributes:true, attributeFilter:['class'] });
  addEventListener('resize',sync);
  document.addEventListener('click', event => {
    if (open && event.target instanceof Element && event.target.closest('#sidebar a[href]')) {
      document.querySelector('#sidebar .native-drawer-close')?.click();
    }
  });
  document.addEventListener('keydown', event => {
    if (!open) return;
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    if (event.key === 'Escape') { event.preventDefault(); sidebar.querySelector('.native-drawer-close')?.click(); }
    if (event.key !== 'Tab') return;
    const nodes = Array.from(sidebar.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]),select:not([disabled])')).filter(node=>node.getClientRects().length);
    const first=nodes[0],last=nodes[nodes.length-1];
    if(event.shiftKey && document.activeElement===first){event.preventDefault();last?.focus();}
    if(!event.shiftKey && document.activeElement===last){event.preventDefault();first?.focus();}
  });
  sync();
})();
