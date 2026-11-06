import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'
import { apply } from '../index.js'

/** Launch-cookie shape the Host mints: prefix plus a 43-character digest. */
function mintedCookie(index) {
  const name = 'dsh-auth-' + createHash('sha256').update(`cookie-${index}`).digest('base64url')
  const payload = Buffer.from(JSON.stringify({ issuedAt: 1_000_000 + index })).toString('base64url')
  return { name, value: `v1.${payload}.signature` }
}

/** A browser jar holding `count` launch cookies, as the handshake receives it. */
function jar(count) {
  return Array.from({ length: count }, (_, index) => {
    const { name, value } = mintedCookie(index)
    return `${name}=${value}`
  }).join('; ')
}

/**
 * Start a listener guarded by the plugin and return its origin.
 *
 * @param handler - route under test.
 * @returns `{ origin, close }` for the server.
 */
async function guarded(handler, logger = { info() {}, warn() {} }) {
  const server = createServer(handler)
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${server.address().port}`

  apply({
    webServer: { server, getOrigin: () => origin },
    logger,
    effect: (fn) => {
      fn()
      return () => {}
    },
  })

  return {
    origin,
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

/** Send the 100-cookie jar and return the response's Set-Cookie lines. */
async function handshake(origin) {
  const response = await fetch(`${origin}/?token=launch-token`, {
    headers: { cookie: jar(100) },
    redirect: 'manual',
  })
  return response.headers.getSetCookie()
}

/** The four newest cookies are kept; every older one must be retired. */
function assertRetired(lines, extra = 0) {
  const deletions = lines.filter((line) => line.includes('Max-Age=0'))
  assert.equal(deletions.length, 96)
  assert.equal(lines.length, 96 + extra)
  for (const index of [96, 97, 98, 99]) {
    const { name } = mintedCookie(index)
    assert.ok(!deletions.some((line) => line.startsWith(`${name}=`)), `kept cookie ${name} was deleted`)
  }
}

test('object-form writeHead (the 303 handshake) keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, {
      location: './',
      'set-cookie': 'dsh-auth-new=1; Path=/',
    })
    res.end()
  })
  try {
    const lines = await handshake(server.origin)
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-new=')).length, 1)
    assertRetired(lines, 1)
  } finally {
    await server.close()
  }
})

test('implicit writeHead (plain 200) keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin))
  } finally {
    await server.close()
  }
})

test('object-form writeHead without set-cookie keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin))
  } finally {
    await server.close()
  }
})

test('three-argument writeHead keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(200, 'OK', { 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin), 1)
  } finally {
    await server.close()
  }
})

test('object writeHead folds case-variant set-cookie keys and array values', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, {
      'Set-Cookie': ['dsh-auth-one=1; Path=/'],
      'set-cookie': 'dsh-auth-two=2; Path=/',
      location: './',
    })
    res.end()
  })
  try {
    const lines = await handshake(server.origin)
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-one=')).length, 1)
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-two=')).length, 1)
    assertRetired(lines, 2)
  } finally {
    await server.close()
  }
})

test('flat-array writeHead keeps the deletions and its own headers', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, ['location', './', 'set-cookie', 'dsh-auth-new=1; Path=/'])
    res.end()
  })
  try {
    const response = await fetch(`${server.origin}/?token=launch-token`, {
      headers: { cookie: jar(100) },
      redirect: 'manual',
    })
    assert.equal(response.status, 303)
    assert.equal(response.headers.get('location'), './')
    const lines = response.headers.getSetCookie()
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-new=')).length, 1)
    assertRetired(lines, 1)
  } finally {
    await server.close()
  }
})

test('three-argument array writeHead keeps the deletions', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(200, 'OK', ['set-cookie', 'dsh-auth-new=1; Path=/'])
    res.end('ok')
  })
  try {
    assertRetired(await handshake(server.origin), 1)
  } finally {
    await server.close()
  }
})

test('appendHeader values survive the implicit writeHead', async () => {
  const server = await guarded((req, res) => {
    res.appendHeader('set-cookie', 'dsh-auth-one=1; Path=/')
    res.appendHeader('set-cookie', 'dsh-auth-two=2; Path=/')
    res.end('ok')
  })
  try {
    const lines = await handshake(server.origin)
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-one=')).length, 1)
    assert.equal(lines.filter((line) => line.startsWith('dsh-auth-two=')).length, 1)
    assertRetired(lines, 2)
  } finally {
    await server.close()
  }
})

test('a request with nothing to retire leaves writeHead untouched', async () => {
  let untouched = false
  const server = await guarded((req, res) => {
    untouched = res.writeHead === Object.getPrototypeOf(res).writeHead
    res.end('ok')
  })
  try {
    const response = await fetch(server.origin, { headers: { cookie: jar(4) } })
    await response.text()
    assert.equal(untouched, true)
  } finally {
    await server.close()
  }
})

test('the current authority cookie survives even when it is the oldest', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end()
  })
  try {
    const currentName = 'dsh-auth-' + createHash('sha256').update(new URL(server.origin).host).digest('base64url')
    const payload = Buffer.from(JSON.stringify({ issuedAt: 0 })).toString('base64url')
    const response = await fetch(`${server.origin}/?token=launch-token`, {
      headers: { cookie: `${currentName}=v1.${payload}.signature; ${jar(100)}` },
      redirect: 'manual',
    })
    const deletions = response.headers.getSetCookie().filter((line) => line.includes('Max-Age=0'))
    assert.equal(deletions.length, 96)
    assert.ok(!deletions.some((line) => line.startsWith(`${currentName}=`)), 'the current authority cookie was deleted')
  } finally {
    await server.close()
  }
})

test('the raised budget admits a cookie header larger than Node default', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end()
  })
  try {
    const response = await fetch(`${server.origin}/?token=launch-token`, {
      headers: { cookie: jar(200) },
      redirect: 'manual',
    })
    const deletions = response.headers.getSetCookie().filter((line) => line.includes('Max-Age=0'))
    assert.equal(response.status, 303)
    assert.equal(deletions.length, 96)
  } finally {
    await server.close()
  }
})

test('a 400-cookie jar drains in bounded chunks without breaking the client', async () => {
  const server = await guarded((req, res) => {
    res.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end()
  })
  try {
    let entries = Array.from({ length: 400 }, (_, index) => {
      const { name, value } = mintedCookie(index)
      return `${name}=${value}`
    })
    let rounds = 0
    while (entries.length > 4) {
      const response = await fetch(`${server.origin}/?token=launch-token`, {
        headers: { cookie: entries.join('; ') },
        redirect: 'manual',
      })
      assert.equal(response.status, 303)
      const deletions = response.headers.getSetCookie().filter((line) => line.includes('Max-Age=0'))
      assert.ok(deletions.length > 0 && deletions.length <= 96, `round ${String(rounds)}: ${String(deletions.length)} deletions`)
      // Apply the deletions the way the browser would before the next request.
      for (const line of deletions) {
        const name = line.slice(0, line.indexOf('='))
        entries = entries.filter((entry) => !entry.startsWith(`${name}=`))
      }
      rounds += 1
      assert.ok(rounds <= 6, `took ${String(rounds)} rounds`)
    }
    assert.equal(rounds, 5)
    assert.equal(entries.length, 4)
  } finally {
    await server.close()
  }
})

test('cookie order, not value claims, decides which cookies are kept', async () => {
  // Payloads claim the opposite order (index 0 is "newest"). A guard that
  // decoded values would keep 0..3; ranking by header position must keep the
  // tail, which is how browsers emit their jar.
  const server = await guarded((req, res) => {
    res.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end()
  })
  try {
    const entries = Array.from({ length: 100 }, (_, index) => {
      const name = 'dsh-auth-' + createHash('sha256').update(`order-${index}`).digest('base64url')
      const payload = Buffer.from(JSON.stringify({ issuedAt: 1_000_000 - index })).toString('base64url')
      return { name, cookie: `${name}=v1.${payload}.signature` }
    })
    const response = await fetch(`${server.origin}/?token=launch-token`, {
      headers: { cookie: entries.map(({ cookie }) => cookie).join('; ') },
      redirect: 'manual',
    })
    const deletions = response.headers.getSetCookie().filter((line) => line.includes('Max-Age=0'))
    assert.equal(deletions.length, 96)
    for (const { name } of entries.slice(0, 96)) {
      assert.ok(deletions.some((line) => line.startsWith(`${name}=`)), `${name} should be retired`)
    }
    for (const { name } of entries.slice(96)) {
      assert.ok(!deletions.some((line) => line.startsWith(`${name}=`)), `${name} should be kept`)
    }
  } finally {
    await server.close()
  }
})

test('cookie names and values never reach the logger', async () => {
  const messages = []
  const server = await guarded(
    (req, res) => {
      res.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-new=1; Path=/' })
      res.end()
    },
    { info: (message) => messages.push(message), warn: (message) => messages.push(message) },
  )
  try {
    await handshake(server.origin)
    assert.ok(messages.length > 0)
    for (const message of messages) {
      assert.ok(!message.includes('dsh-auth-'), `cookie name leaked: ${message}`)
      assert.ok(!message.includes('v1.'), `cookie value leaked: ${message}`)
    }
  } finally {
    await server.close()
  }
})

/** Resolve after `ms`, for the deferred-binding cases. */
function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

/**
 * Apply the plugin to a context whose `webServer` has not bound a listener yet,
 * the way a composition can load this row before `[Service.init]` runs.
 *
 * @returns the mutable context plus the dispose the effect registered.
 */
function unboundContext(logger = { info() {}, warn() {}, error() {} }) {
  const webServer = {}
  const ctx = {
    webServer,
    logger,
    effect: (fn) => {
      ctx.dispose = fn()
      return () => {}
    },
  }
  apply(ctx)
  return ctx
}

test('a listener that binds after apply is raised and prunes on its first request', async () => {
  const messages = []
  const ctx = unboundContext({ info: (message) => messages.push(message), warn() {}, error() {} })
  const server = createServer((req, res) => {
    res.writeHead(303, { location: './', 'set-cookie': 'dsh-auth-new=1; Path=/' })
    res.end()
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    ctx.webServer.server = server
    ctx.webServer.getOrigin = () => `http://127.0.0.1:${server.address().port}`
    await sleep(250)

    assert.equal(server.maxHeaderSize, 65536)
    assert.ok(messages.some((message) => message.includes('waiting for webServer to bind')))

    const response = await fetch(`${ctx.webServer.getOrigin()}/?token=launch-token`, {
      headers: { cookie: jar(10) },
      redirect: 'manual',
    })
    const deletions = response.headers.getSetCookie().filter((line) => line.includes('Max-Age=0'))
    assert.equal(deletions.length, 6)
  } finally {
    ctx.dispose?.()
    await new Promise((resolve) => server.close(resolve))
  }
})

test('disposing restores the listener budget it raised', async () => {
  const ctx = unboundContext()
  const server = createServer((req, res) => {
    res.end('ok')
  })
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  try {
    ctx.webServer.server = server
    await sleep(250)
    assert.equal(server.maxHeaderSize, 65536)
  } finally {
    ctx.dispose?.()
    assert.equal(server.maxHeaderSize, undefined)
    await new Promise((resolve) => server.close(resolve))
  }
})

test('a listener that already carries a larger budget keeps it, and keeps it after dispose', async () => {
  const server = createServer((req, res) => {
    res.end('ok')
  })
  server.maxHeaderSize = 200_000
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const origin = `http://127.0.0.1:${server.address().port}`
  const ctx = {
    webServer: { server, getOrigin: () => origin },
    logger: { info() {}, warn() {}, error() {} },
    effect: (fn) => {
      ctx.dispose = fn()
      return () => {}
    },
  }
  try {
    apply(ctx)
    assert.equal(server.maxHeaderSize, 200_000)
  } finally {
    ctx.dispose?.()
    assert.equal(server.maxHeaderSize, 200_000)
    await new Promise((resolve) => server.close(resolve))
  }
})

test('a replaced listener is guarded again on the next apply', async () => {
  // A composition reload disposes this fiber and applies it again, so the guard
  // has to be re-entrant: the previous listener must be released and the new one
  // taken under guard.
  const first = createServer((req, res) => {
    res.end('ok')
  })
  await new Promise((resolve) => first.listen(0, '127.0.0.1', resolve))
  const second = createServer((req, res) => {
    res.end('ok')
  })
  await new Promise((resolve) => second.listen(0, '127.0.0.1', resolve))
  try {
    const firstCtx = unboundContext()
    firstCtx.webServer.server = first
    await sleep(250)
    assert.equal(first.maxHeaderSize, 65536)
    firstCtx.dispose?.()
    assert.equal(first.maxHeaderSize, undefined)

    const secondCtx = unboundContext()
    secondCtx.webServer.server = second
    await sleep(250)
    assert.equal(second.maxHeaderSize, 65536)
    secondCtx.dispose?.()
    assert.equal(second.maxHeaderSize, undefined)
  } finally {
    await new Promise((resolve) => first.close(resolve))
    await new Promise((resolve) => second.close(resolve))
  }
})
