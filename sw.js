/* sw.js — Production, 2025-08-18 */
self.__WB_DISABLE_DEV_LOGS = true;

// Workbox v7
importScripts('https://storage.googleapis.com/workbox-cdn/releases/7.1.0/workbox-sw.js');

if (self.workbox) {
  const { core, routing, strategies, precaching, expiration, cacheableResponse, backgroundSync } = self.workbox;

  // Fast updates
  core.skipWaiting();
  core.clientsClaim();

  // Consistent cache names
  core.setCacheNameDetails({
    prefix: 'biovault',
    suffix: 'v1',
    precache: 'precache',
    runtime: 'runtime',
  });

  // Precache (filled at build; empty is fine too)
  precaching.precacheAndRoute(self.__WB_MANIFEST || []);

  // HTML navigation: NetworkFirst + small timeout, falls back to offline page if available
  routing.registerRoute(
    ({ request }) => request.mode === 'navigate',
    new strategies.NetworkFirst({
      cacheName: 'biovault-pages',
      networkTimeoutSeconds: 3,
      plugins: [
        new expiration.ExpirationPlugin({ maxEntries: 50, purgeOnQuotaError: true }),
      ],
    })
  );

  // Scripts & styles: SWR
  routing.registerRoute(
    ({ request }) => request.destination === 'script' || request.destination === 'style',
    new strategies.StaleWhileRevalidate({
      cacheName: 'biovault-assets',
      plugins: [
        new expiration.ExpirationPlugin({ maxEntries: 100, purgeOnQuotaError: true }),
      ],
    })
  );

  // Images: CacheFirst with expiration
  routing.registerRoute(
    ({ request }) => request.destination === 'image',
    new strategies.CacheFirst({
      cacheName: 'biovault-images',
      plugins: [
        new expiration.ExpirationPlugin({
          maxEntries: 150,
          maxAgeSeconds: 60 * 24 * 60 * 60, // 60 days
          purgeOnQuotaError: true,
        }),
      ],
    })
  );

  // Fonts (Google/CDN): CacheFirst + cacheable 0/200
  routing.registerRoute(
    ({ url }) =>
      url.origin.includes('fonts.googleapis.com') ||
      url.origin.includes('fonts.gstatic.com'),
    new strategies.CacheFirst({
      cacheName: 'biovault-fonts',
      plugins: [
        new cacheableResponse.CacheableResponsePlugin({ statuses: [0, 200] }),
        new expiration.ExpirationPlugin({ maxEntries: 20, purgeOnQuotaError: true }),
      ],
    })
  );

  // Background Sync: queue POSTs to /api/tx/
  const txQueue = new backgroundSync.BackgroundSyncPlugin('txQueue', {
    maxRetentionTime: 24 * 60, // minutes
  });
  routing.registerRoute(
    ({ url, request }) => request.method === 'POST' && url.pathname.startsWith('/api/tx/'),
    new strategies.NetworkOnly({ plugins: [txQueue] }),
    'POST'
  );

  // Offline fallbacks
  routing.setCatch(async ({ event }) => {
    if (event.request.destination === 'document') {
      // Try a precached offline page if you add one at /offline.html
      const cache = await caches.open(core.cacheNames.precache);
      const offline = await cache.match('/offline.html');
      if (offline) return offline;
      return new Response('<h1>Offline</h1><p>Please check your connection.</p>', {
        headers: { 'Content-Type': 'text/html; charset=UTF-8' },
      });
    }
    return Response.error();
  });

  // Allow page to trigger immediate activation
  self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'SKIP_WAITING') self.skipWaiting();
  });

  // Push notifications (defensive parsing)
  self.addEventListener('push', (event) => {
    let data = {};
    try {
      data = event.data ? event.data.json() : {};
    } catch (_) {}
    const title = data.title || 'BioVault';
    const options = {
      body: data.body || 'You have a new notification.',
      icon: data.icon || 'icon-192.png',
      badge: data.badge || 'icon-72.png',
      data: data.data || {},
    };
    event.waitUntil(self.registration.showNotification(title, options));
  });

  // Focus/open app when user clicks a notification
  self.addEventListener('notificationclick', (event) => {
    event.notification.close();
    event.waitUntil((async () => {
      const all = await clients.matchAll({ type: 'window', includeUncontrolled: true });
      const targetURL = (event.notification && event.notification.data && event.notification.data.url) || '/';
      const match = all.find(c => new URL(c.url).pathname === new URL(targetURL, location.origin).pathname);
      if (match) return match.focus();
      return clients.openWindow(targetURL);
    })());
  });

} else {
  // Fallback if Workbox CDN failed (very minimal)
  self.addEventListener('install', (e) => e.waitUntil(self.skipWaiting()));
  self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
  self.addEventListener('fetch', (event) => {
    event.respondWith(fetch(event.request).catch(() => caches.match(event.request)));
  });
}
