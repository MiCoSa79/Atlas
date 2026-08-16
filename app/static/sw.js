// Service Worker für Atlas Web Push (v0.0.68)
// Zeigt Push-Benachrichtigungen an, wenn die App im Hintergrund ist.

self.addEventListener('push', function(event) {
    const data = event.data ? event.data.json() : { title: 'Atlas', body: 'Neue Nachricht' };
    event.waitUntil(
        self.registration.showNotification(data.title || 'Atlas', {
            body: data.body || '',
            icon: '/favicon.ico',
            badge: '/favicon.ico',
            tag: 'atlas-reply',
            requireInteraction: false,
            data: { url: '/' }
        })
    );
});

self.addEventListener('notificationclick', function(event) {
    event.notification.close();
    event.waitUntil(
        self.clients.matchAll({ type: 'window', includeUncontrolled: true })
            .then(function(clientList) {
                for (const client of clientList) {
                    if (client.url.includes('/') && 'focus' in client) return client.focus();
                }
                return self.clients.openWindow('/');
            })
    );
});