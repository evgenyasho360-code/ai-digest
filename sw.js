self.addEventListener('push', event => {
  const data = event.data ? event.data.json() : {}
  const title = data.title || 'AI Builders Digest'
  const options = {
    body: data.body || '今日 digest 已更新，点击查看',
    icon: '/ai-digest/icon-192.png',
    badge: '/ai-digest/icon-192.png',
    data: { url: data.url || 'https://evgenyasho360-code.github.io/ai-digest/' },
  }
  event.waitUntil(self.registration.showNotification(title, options))
})

self.addEventListener('notificationclick', event => {
  event.notification.close()
  const url = event.notification.data?.url || 'https://evgenyasho360-code.github.io/ai-digest/'
  event.waitUntil(clients.openWindow(url))
})
