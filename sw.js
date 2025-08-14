// sw.js
importScripts('https://storage.googleapis.com/workbox-cdn/releases/6.5.4/workbox-sw.js');

workbox.routing.registerRoute(
  ({request}) => request.mode === 'navigate',
  new workbox.strategies.NetworkFirst()
);

workbox.routing.registerRoute(
  ({request}) => request.destination === 'script' || request.destination === 'style' || request.destination === 'image',
  new workbox.strategies.StaleWhileRevalidate({cacheName: 'assets-cache'})
);

workbox.precaching.precacheAndRoute(self.__WB_MANIFEST || []);

self.addEventListener('install', (event) => {
  console.log('📦 Service Worker Installed');
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});

// Background sync for transactions and P2P payloads
const bgSyncPlugin = new workbox.backgroundSync.BackgroundSyncPlugin('txQueue', {
  maxRetentionTime: 24 * 60 // Retry for 24 hours
});

workbox.routing.registerRoute(
  new RegExp('/api/tx/'), // Placeholder for tx endpoint if relay used
  new workbox.strategies.NetworkOnly({
    plugins: [bgSyncPlugin]
  }),
  'POST'
);

// Push notifications handler
self.addEventListener('push', (event) => {
  const data = event.data.json();
  const options = {
    body: data.body,
    icon: 'icon-192.png'
  };
  event.waitUntil(self.registration.showNotification(data.title, options));
});
