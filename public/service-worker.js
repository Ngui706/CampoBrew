const CACHE_NAME = 'techsips-v1';
const APP_SHELL = [
    '/',
    '/index.html',
    '/products.html',
    '/checkout.html',
    '/style.css',
    '/index.js',
    '/product.js',
    '/checkout.js',
    '/manifest.webmanifest',
    '/icons/icon-192.svg',
    '/icons/icon-512.svg'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
    );
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((keys) => Promise.all(
            keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
        ))
    );
    self.clients.claim();
});

self.addEventListener('fetch', (event) => {
    const request = event.request;

    if (request.method !== 'GET') return;
    if (new URL(request.url).pathname.startsWith('/api/')) return;

    event.respondWith(
        caches.match(request).then((cached) => cached || fetch(request).then((response) => {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
            return response;
        }).catch(() => caches.match('/index.html')))
    );
});
