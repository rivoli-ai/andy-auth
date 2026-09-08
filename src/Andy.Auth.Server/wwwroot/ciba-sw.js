self.addEventListener('push', event => {
    event.waitUntil((async () => {
        const message = event.data?.json();
        if (!message) return;
        const url = new URL(message.url);
        const scope = new URL(self.registration.scope);
        if (url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname + 'Approve/')) return;
        await self.registration.showNotification('Sign-in approval', {
            body: String(message.body || 'Review the request before approving.'),
            tag: String(message.tag), data: { url: url.href }
        });
    })());
});
self.addEventListener('notificationclick', event => {
    event.notification.close();
    event.waitUntil((async () => {
        const url = new URL(event.notification.data.url);
        const scope = new URL(self.registration.scope);
        if (url.origin === scope.origin && url.pathname.startsWith(scope.pathname + 'Approve/')) await clients.openWindow(url.href);
    })());
});
