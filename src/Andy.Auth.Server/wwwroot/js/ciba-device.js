(() => {
    const form = document.getElementById('push-enrollment');
    if (!form) return;
    const status = document.getElementById('push-status');
    form.addEventListener('submit', async event => {
        if (event.submitter?.hasAttribute('formaction')) return;
        event.preventDefault();
        try {
            if (!('serviceWorker' in navigator) || !('PushManager' in window)) throw new Error('This browser does not support push notifications.');
            const permission = await Notification.requestPermission();
            if (permission !== 'granted') throw new Error('Allow notifications to register this device.');
            const registration = await navigator.serviceWorker.register(form.dataset.root + 'ciba-sw.js', { scope: form.dataset.root + 'Ciba/' });
            if (!registration.active) await new Promise((resolve, reject) => {
                const worker = registration.installing || registration.waiting;
                if (!worker) return reject(new Error('Notification worker did not install. Try again.'));
                const changed = () => {
                    if (worker.state === 'activated' || worker.state === 'redundant') {
                        worker.removeEventListener('statechange', changed);
                        if (worker.state === 'activated') resolve();
                        else reject(new Error('Notification worker installation failed. Try again.'));
                    }
                };
                worker.addEventListener('statechange', changed);
                changed();
            });
            const raw = form.dataset.key.replace(/-/g, '+').replace(/_/g, '/');
            const key = Uint8Array.from(atob(raw + '='.repeat((4 - raw.length % 4) % 4)), char => char.charCodeAt(0));
            let subscription = await registration.pushManager.getSubscription();
            if (subscription) {
                const priorKey = new Uint8Array(subscription.options.applicationServerKey || new ArrayBuffer(0));
                if (priorKey.length !== key.length || priorKey.some((value, index) => value !== key[index])) {
                    await subscription.unsubscribe();
                    subscription = null;
                }
            }
            subscription ||= await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
            const json = subscription.toJSON();
            const body = new FormData(form);
            body.set('endpoint', json.endpoint);
            body.set('p256dh', json.keys.p256dh);
            body.set('auth', json.keys.auth);
            const response = await fetch(form.action, { method: 'POST', body, credentials: 'same-origin', redirect: 'error' });
            if (!response.ok) throw new Error('Registration failed. Check your password and authenticator code, then try again.');
            form.querySelector('[name=password]').value = '';
            form.querySelector('[name=code]').value = '';
            status.textContent = 'This device is registered for sign-in approvals.';
        } catch (error) { status.textContent = error.message || 'Could not register this device.'; }
    });
})();
