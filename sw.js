// CSFA Command Center service worker.
// Caches only the app shell and its libraries so the app opens fast and installs as a PWA.
// Supabase traffic is never cached: admin data is private and must always be live.
// Bump VERSION whenever this file or the shell list changes.
const VERSION = 'csfa-command-v1';
const SHELL_CACHE = `${VERSION}-shell`;
const CDN_CACHE = `${VERSION}-cdn`;

const SHELL = [
    './',
    './index.html',
    './manifest.webmanifest',
    './icons/icon-192.png',
    './icons/icon-512.png',
    './icons/icon-maskable-512.png',
    './icons/apple-touch-icon.png',
    './icons/favicon-32.png'
];

const CDN_HOSTS = ['cdn.tailwindcss.com', 'unpkg.com', 'cdn.jsdelivr.net'];

self.addEventListener('install', event => {
    event.waitUntil(caches.open(SHELL_CACHE).then(cache => cache.addAll(SHELL)));
    // No skipWaiting here: the page asks the admin before switching to a new version.
});

self.addEventListener('activate', event => {
    event.waitUntil((async () => {
        const keys = await caches.keys();
        await Promise.all(keys.filter(k => !k.startsWith(VERSION)).map(k => caches.delete(k)));
        await self.clients.claim();
    })());
});

self.addEventListener('message', event => {
    if (event.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', event => {
    const req = event.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);

    // Live, private data: always straight to the network.
    if (url.hostname.endsWith('.supabase.co') || url.hostname.endsWith('.supabase.in')) return;

    // Page loads: newest page when online, cached shell when offline.
    if (req.mode === 'navigate' && url.origin === self.location.origin) {
        event.respondWith((async () => {
            try {
                const fresh = await fetch(req);
                if (fresh.ok) (await caches.open(SHELL_CACHE)).put('./index.html', fresh.clone());
                return fresh;
            } catch {
                return (await caches.match('./index.html')) || (await caches.match('./')) || Response.error();
            }
        })());
        return;
    }

    // Own static files (icons, manifest): cache first.
    if (url.origin === self.location.origin) {
        event.respondWith((async () => {
            const cached = await caches.match(req);
            if (cached) return cached;
            const res = await fetch(req);
            if (res.ok) (await caches.open(SHELL_CACHE)).put(req, res.clone());
            return res;
        })());
        return;
    }

    // Libraries from CDNs: serve cached copy, refresh in the background.
    if (CDN_HOSTS.includes(url.hostname)) {
        event.respondWith((async () => {
            const cache = await caches.open(CDN_CACHE);
            const cached = await cache.match(req);
            const network = fetch(req)
                .then(res => {
                    if (res.ok || res.type === 'opaque') cache.put(req, res.clone());
                    return res;
                })
                .catch(() => cached || Response.error());
            return cached || network;
        })());
    }
});
