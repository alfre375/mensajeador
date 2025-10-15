// service-worker.js
self.addEventListener('push', event => {
    let data = { title: 'Nuevo mensaje', body: 'Toca para abrir', url: '/', icon: '/icon.png' };
    if (event.data) {
        try {
            data = event.data.json();
        } catch (e) {
            data = { title: 'Nuevo mensaje', body: event.data.text() };
        }
    }

    const options = {
        body: data.body,
        icon: data.icon,
        data: { url: data.url, ...data.data },
        badge: data.badge
    };

    event.waitUntil(
        self.registration.showNotification(data.title, options)
    );
});

self.addEventListener('notificationclick', event => {
    event.notification.close();
    const url = event.notification.data && event.notification.data.url ? event.notification.data.url : '/';
    event.waitUntil(
        clients.matchAll({ type: 'window', includeUncontrolled: true }).then(windowClients => {
            // Si hay una ventana abierta, enfoque la primera
            for (let client of windowClients) {
                if (client.url === url && 'focus' in client) return client.focus();
            }
            // Si no, abrir nueva
            if (clients.openWindow) return clients.openWindow(url);
        })
    );
});