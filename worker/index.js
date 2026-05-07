/**
 * AI Builders Digest — Push Notification Worker
 *
 * Required secrets (set via `wrangler secret put <NAME>`):
 *   VAPID_PUBLIC_KEY  — uncompressed P-256 public key, base64url (87 chars)
 *   VAPID_PRIVATE_KEY — raw P-256 private scalar, base64url (43 chars)
 *   VAPID_SUBJECT     — "mailto:you@example.com"
 *   NOTIFY_SECRET     — arbitrary token to protect the /notify endpoint
 *
 * KV namespace binding: SUBSCRIPTIONS
 */

const ORIGIN = 'https://evgenyasho360-code.github.io'
const SITE_URL = 'https://evgenyasho360-code.github.io/ai-digest/'

const CORS = {
  'Access-Control-Allow-Origin': ORIGIN,
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS })
    }
    const { pathname } = new URL(request.url)
    try {
      if (pathname === '/subscribe'   && request.method === 'POST') return handleSubscribe(request, env)
      if (pathname === '/unsubscribe' && request.method === 'POST') return handleUnsubscribe(request, env)
      if (pathname === '/notify'      && request.method === 'POST') return handleNotify(request, env)
      if (pathname === '/count'       && request.method === 'GET')  return handleCount(env)
    } catch (e) {
      return reply({ error: e.message }, 500)
    }
    return new Response('Not found', { status: 404 })
  },
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async function handleSubscribe(req, env) {
  const sub = await req.json()
  if (!sub?.endpoint || !sub?.keys?.p256dh || !sub?.keys?.auth) {
    return reply({ error: 'Invalid subscription object' }, 400)
  }
  const key = await shortHash(sub.endpoint)
  await env.SUBSCRIPTIONS.put(key, JSON.stringify(sub))
  return reply({ ok: true })
}

async function handleUnsubscribe(req, env) {
  const { endpoint } = await req.json()
  if (!endpoint) return reply({ error: 'Missing endpoint' }, 400)
  await env.SUBSCRIPTIONS.delete(await shortHash(endpoint))
  return reply({ ok: true })
}

async function handleCount(env) {
  const { keys } = await env.SUBSCRIPTIONS.list()
  return reply({ subscribers: keys.length })
}

async function handleNotify(req, env) {
  const body = await req.json()
  if (body.secret !== env.NOTIFY_SECRET) return reply({ error: 'Unauthorized' }, 401)

  const payload = JSON.stringify({
    title: body.title ?? 'AI Builders Digest',
    body:  body.body  ?? '今日 digest 已更新，点击查看',
    url:   body.url   ?? SITE_URL,
  })

  const { keys } = await env.SUBSCRIPTIONS.list()
  let sent = 0, removed = 0, failed = 0

  for (const { name } of keys) {
    const raw = await env.SUBSCRIPTIONS.get(name)
    if (!raw) continue
    const sub = JSON.parse(raw)
    try {
      const status = await sendPush(env, sub, payload)
      if (status === 201 || status === 200 || status === 202) {
        sent++
      } else if (status === 410 || status === 404) {
        await env.SUBSCRIPTIONS.delete(name)
        removed++
      } else {
        failed++
      }
    } catch {
      failed++
    }
  }

  return reply({ sent, removed, failed })
}

// ── Web Push (RFC 8291 + VAPID) ───────────────────────────────────────────────

async function sendPush(env, sub, payload) {
  const audience = new URL(sub.endpoint).origin
  const jwt = await buildVapidJwt(
    env.VAPID_PRIVATE_KEY, env.VAPID_PUBLIC_KEY, env.VAPID_SUBJECT, audience
  )
  const body = await encryptPayload(
    b64u_dec(sub.keys.p256dh),
    b64u_dec(sub.keys.auth),
    payload
  )
  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Content-Type':     'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL':              '86400',
      'Urgency':          'normal',
      'Authorization':    `vapid t=${jwt},k=${env.VAPID_PUBLIC_KEY}`,
    },
    body,
  })
  return res.status
}

// ES256 JWT for VAPID authentication
async function buildVapidJwt(privB64, pubB64, subject, audience) {
  const pub  = b64u_dec(pubB64)
  const priv = b64u_dec(privB64)

  // Construct JWK from raw keys (pub = 0x04 || x || y, 65 bytes)
  const jwk = {
    kty: 'EC', crv: 'P-256', ext: true,
    d: b64u_enc(priv),
    x: b64u_enc(pub.slice(1, 33)),
    y: b64u_enc(pub.slice(33, 65)),
    key_ops: ['sign'],
  }
  const signingKey = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']
  )

  const header  = b64u_enc(te('{"alg":"ES256","typ":"JWT"}'))
  const claims  = b64u_enc(te(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 43200,
    sub: subject,
  })))
  const sigInput = `${header}.${claims}`
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    signingKey,
    te(sigInput)
  )
  return `${sigInput}.${b64u_enc(new Uint8Array(sig))}`
}

// RFC 8291 payload encryption (aes128gcm)
async function encryptPayload(receiverPub, authSecret, plaintext) {
  // Ephemeral sender ECDH key pair
  const senderKP  = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  )
  const senderPub = new Uint8Array(await crypto.subtle.exportKey('raw', senderKP.publicKey))

  // ECDH shared secret
  const receiverKey = await crypto.subtle.importKey(
    'raw', receiverPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  )
  const ecdhSecret = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'ECDH', public: receiverKey }, senderKP.privateKey, 256)
  )

  // RFC 8291 §3.3: derive IKM
  const prkKey = await hkdfExtract(authSecret, ecdhSecret)
  const ikm    = await hkdfExpand(prkKey, concat(te('WebPush: info\0'), receiverPub, senderPub), 32)

  // RFC 8188: salt → CEK + nonce
  const salt  = crypto.getRandomValues(new Uint8Array(16))
  const prk   = await hkdfExtract(salt, ikm)
  const cek   = await hkdfExpand(prk, te('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdfExpand(prk, te('Content-Encoding: nonce\0'), 12)

  // Encrypt: plaintext ++ 0x02 delimiter (single record)
  const cekKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce },
      cekKey,
      concat(te(plaintext), new Uint8Array([2]))
    )
  )

  // RFC 8188 binary header: salt(16) | rs(4BE) | idlen(1) | keyid(65) | ciphertext
  const rs = new Uint8Array(4)
  new DataView(rs.buffer).setUint32(0, 4096, false)
  return concat(salt, rs, new Uint8Array([senderPub.length]), senderPub, ct)
}

// ── HKDF via HMAC (RFC 5869) ──────────────────────────────────────────────────

async function hkdfExtract(salt, ikm) {
  const key = await crypto.subtle.importKey(
    'raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, ikm))
}

async function hkdfExpand(prk, info, len) {
  const key = await crypto.subtle.importKey(
    'raw', prk, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  )
  let t = new Uint8Array(0)
  const out = new Uint8Array(len)
  let pos = 0
  for (let i = 1; pos < len; i++) {
    t = new Uint8Array(await crypto.subtle.sign('HMAC', key, concat(t, info, new Uint8Array([i]))))
    const take = Math.min(t.length, len - pos)
    out.set(t.subarray(0, take), pos)
    pos += take
  }
  return out
}

// ── Utilities ─────────────────────────────────────────────────────────────────

const te = s => new TextEncoder().encode(s)

function concat(...arrays) {
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0))
  let i = 0
  for (const a of arrays) { out.set(a, i); i += a.length }
  return out
}

function b64u_dec(s) {
  const p = s.replace(/-/g, '+').replace(/_/g, '/')
  const pad = p.length % 4 ? '='.repeat(4 - p.length % 4) : ''
  return Uint8Array.from(atob(p + pad), c => c.charCodeAt(0))
}

function b64u_enc(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data)
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function shortHash(s) {
  const buf = await crypto.subtle.digest('SHA-256', te(s))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 32)
}

function reply(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}
