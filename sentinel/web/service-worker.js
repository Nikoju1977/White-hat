const CACHE = 'aegis-static-v1';
const FILES = ['/', '/static/style.css', '/static/app.js', '/static/icon-192.png'];
self.addEventListener('install', e => e.waitUntil(caches.open(CACHE).then(c=>c.addAll(FILES))));
self.addEventListener('activate', e => e.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE).map(k=>caches.delete(k))))));
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if(e.request.method!=='GET' || url.origin!==self.location.origin || url.pathname.startsWith('/api/')) return;
  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
});
