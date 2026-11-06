/**
 * auth-cookie-guard — keep the local Host's launch cookies from locking a
 * profile out of the desktop welcome handshake.
 *
 * ## The failure this repairs
 *
 * The Host binds an OS-assigned port on every start, and the browser-session
 * cookie is named after that authority:
 * `dsh-auth-<base64url(sha256(host:port))>` (dsh-client-connection/lib/index.js:277,
 * :335-337). Browsers store cookies per host and never per port, so every start
 * leaves one more ~173-character cookie for `127.0.0.1` with a 30-day
 * `Max-Age`, and nothing ever removes one.
 *
 * The Host builds its listener without a header-budget override —
 * `createServer(listener)` at dsh-host-webserver/lib/index.js:412 — so Node's
 * default `maxHeaderSize` of 16384 bytes governs. Around the 71st start the
 * `Cookie` header alone is 16184 bytes; the next handshake appends one more
 * cookie and reaches 16411 bytes, Node answers `431`, the desktop client reads
 * that as `desktop welcome: Web authentication failed`, and the profile stays
 * locked out because the jar only grows: the welcome page is never reached to
 * prune it, and there is no other code path that removes cookies.
 *
 * ## What this plugin does
 *
 * 1. Raises the listener's header budget (`maxHeaderBytes`, 64 KiB by default).
 *    Node reads `server.maxHeaderSize` per connection, so assigning it on the
 *    live server takes effect immediately — including for the handshake that
 *    would otherwise be answered with 431.
 * 2. Retires stale launch cookies on every request. Minted names are
 *    `dsh-auth-<43 base64url characters>`; browsers list their jar oldest
 *    first (RFC 6265 section 5.4) and every launch cookie uses `Path=/`, so
 *    the tail of the header is the newest set. Everything except the newest
 *    `keep` is deleted in the browser jar with `Max-Age=0`, so the jar shrinks
 *    at the first successful handshake instead of growing without bound.
 *
 * It never decodes a cookie value: only the name is needed to rank the jar,
 * and the value is the signed session payload (`authority`, `issuedAt`,
 * `expiresAt`). The guard therefore cannot read, log, or act on login state.
 *
 * Neither half is sufficient alone, which is why both are installed: raising the
 * budget only postpones the wall (~350 starts instead of ~72), and pruning alone
 * can never run, because a connection rejected with 431 never reaches the
 * listener.
 *
 * The guard also binds late rather than not at all: `webServer` is registered
 * before `[Service.init]` binds its socket, so a composition that loads this row
 * early would otherwise find `webServer.server` unset and guard nothing while
 * still looking installed. It now waits for the listener (bounded) and reports
 * loudly if it never appears.
 *
 * ## What it deliberately does not do
 *
 * It never decodes a cookie value, renames, re-signs, or rewrites a cookie it
 * keeps, and it never touches a cookie whose name is not the exact minted
 * shape — a future format change degrades to "budget raised, nothing retired"
 * rather than to a broken session. It also keeps the cookie belonging to the
 * current authority even when that cookie is not among the newest `keep`, so
 * the running instance cannot delete the very cookie it is authenticating with.
 */

import { createHash } from 'node:crypto'

/** Loader display name. */
export const name = 'auth-cookie-guard'

/** The listener this plugin guards; the service is live before it applies. */
export const inject = ['webServer']

/** Prefix of the launch cookies minted by the Host. */
const PREFIX = 'dsh-auth-'

/** Exactly the minted shape: the prefix plus a sha256 digest in base64url. */
const MINTED = /^dsh-auth-[A-Za-z0-9_-]{43}$/

/** Defaults, overridable from the profile patch row. */
const DEFAULTS = {
  maxHeaderBytes: 64 * 1024,
  keep: 4,
}

/** Bounds that keep a misconfiguration from disabling either guard. */
const LIMITS = {
  maxHeaderBytes: [16 * 1024, 1024 * 1024],
  keep: [1, 64],
}

/** Attributes that delete a cookie for its exact host and path. */
const EXPIRATION = 'Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'

/**
 * Cap per response so a huge jar cannot produce an unbounded reply.
 *
 * `dsh-auth-` plus 43 digest characters is the only name shape accepted, so
 * one deletion line is ~125 bytes on the wire; 96 of them stay near 12 KiB.
 * That clears the 16 KiB default response-header budget of Node HTTP clients
 * (a 128-line reply made `fetch` fail to decode the handshake) and is far
 * below what browsers accept. A jar larger than this drains across later
 * requests instead of risking one oversized response.
 */
const MAX_RETIRE_PER_RESPONSE = 96

/**
 * How often a not-yet-bound listener is re-checked.
 *
 * `webServer` is registered before `[Service.init]` binds the socket, so the
 * guard may apply while `webServer.server` is still unset. The re-check is a
 * cheap property read once per interval, and it stops as soon as the listener
 * appears.
 */
const RECHECK_MS = 100

/**
 * How many re-checks (10 s at this interval) before reporting the listener as
 * missing. Bounded on purpose: a guard that silently never applies is worse than
 * a loud failure, because the desktop welcome stays locked out either way and
 * only the log can say why.
 */
const RECHECK_LIMIT = 100

/**
 * Guard the local listener.
 *
 * The `webServer` service is registered as soon as it is constructed but binds
 * its socket in `[Service.init]`, so depending on a composition's load order
 * this plugin can apply while `webServer.server` is still `undefined`. Bailing
 * out there is the difference between a guard that works and one that looks
 * installed but silently guards nothing, so the listener is picked up as soon
 * as it appears instead: the guard binds immediately when it can, and otherwise
 * re-checks on a short timer (bounded, so a listener that never binds is
 * reported instead of waited on forever).
 *
 * @param ctx - plugin context; `webServer` is the live service.
 * @param config - optional `{ maxHeaderBytes, keep }` overrides.
 */
export function apply(ctx, config = {}) {
  const maxHeaderBytes = bounded(config.maxHeaderBytes, DEFAULTS.maxHeaderBytes, LIMITS.maxHeaderBytes)
  const keep = bounded(config.keep, DEFAULTS.keep, LIMITS.keep)

  /** The listener currently guarded; `undefined` before the service binds. */
  let guarded
  /** The listener's own budget before this plugin raised it. */
  let previous
  /** The budget this plugin assigned, restored only while it is still in force. */
  let applied
  /** Pending re-check for a listener that has not bound yet. */
  let timer
  /** Number of re-checks spent waiting for the listener. */
  let waited = 0

  /**
   * Delete the launch cookies this instance will never authenticate on the
   * response that answers the current request.
   *
   * @param req - incoming request carrying the browser jar.
   * @param res - response being prepared; deletions are merged when it writes
   *   its headers, so an object-form `writeHead` cannot replace them.
   */
  function retire(req, res) {
    const header = req.headers.cookie
    if (typeof header !== 'string' || !header.includes(PREFIX)) return

    const names = []
    for (const segment of header.split(';')) {
      const at = segment.indexOf('=')
      if (at === -1) continue
      const name = segment.slice(0, at).trim()
      if (MINTED.test(name)) names.push(name)
    }
    if (names.length === 0) return

    // Resolved per request, exactly as the Host resolves it: the protocol the
    // listener actually serves, and the authority this request arrived on, so a
    // page opened on `localhost` instead of `127.0.0.1` still protects the
    // cookie it is using. The listener's own origin is the fallback for requests
    // that carry no Host header.
    const protocol = originProtocol(ctx.webServer)
    const current = cookieNameOf(protocol, req.headers.host) ?? cookieNameOf(protocol, boundHost(ctx.webServer))

    // Browsers emit the jar oldest first (RFC 6265 section 5.4), so the tail
    // holds the newest launches; the current authority is kept by name even
    // when it is not in that tail.
    const retained = new Set(names.slice(-keep))
    if (current !== undefined) retained.add(current)

    const stale = [...new Set(names)].filter((name) => !retained.has(name))
    if (stale.length === 0) return

    const lines = stale
      .slice(0, MAX_RETIRE_PER_RESPONSE)
      .map((name) => `${name}=; ${EXPIRATION}`)
    armCookies(res, lines)
    ctx.logger?.info?.(
      `auth-cookie-guard: retired ${String(lines.length)} launch cookie(s), kept ${String(retained.size)}`,
    )
  }

  /**
   * Stop guarding the listener picked up earlier, restoring its own budget.
   *
   * @returns nothing.
   */
  function release() {
    if (guarded === undefined) return
    guarded.removeListener('request', retire)
    if (guarded.maxHeaderSize === applied) guarded.maxHeaderSize = previous
    guarded = undefined
    previous = undefined
    applied = undefined
  }

  /**
   * Take the service's listener under guard, if it has one by now.
   *
   * Node reads `maxHeaderSize` per connection, so the assigned value applies to
   * connections that have not been accepted yet — the handshake this plugin is
   * trying to rescue. A listener that already carries a larger budget keeps it:
   * this plugin only ever raises the ceiling.
   *
   * @returns whether the listener is under guard after this call.
   */
  function bind() {
    const server = ctx.webServer?.server
    if (server === undefined || server === null) return false
    if (server === guarded) return true

    release()
    const own = Number(server.maxHeaderSize)
    previous = server.maxHeaderSize
    applied = Number.isFinite(own) && own > maxHeaderBytes ? own : maxHeaderBytes
    server.maxHeaderSize = applied
    server.prependListener('request', retire)
    guarded = server

    ctx.logger?.info?.(
      `auth-cookie-guard: listener header budget ${String(applied)} bytes, keeping ${String(keep)} launch cookie(s)`,
    )
    return true
  }

  ctx.effect(() => {
    if (bind()) return release

    ctx.logger?.info?.(
      `auth-cookie-guard: waiting for webServer to bind, then raising its header budget to ${String(maxHeaderBytes)} bytes`,
    )
    timer = setInterval(() => {
      waited += 1
      if (bind()) {
        clearInterval(timer)
        timer = undefined
        return
      }
      if (waited < RECHECK_LIMIT) return
      clearInterval(timer)
      timer = undefined
      ctx.logger?.error?.(
        'auth-cookie-guard: webServer never exposed a listener, so the header budget is NOT raised and stale launch cookies are NOT retired',
      )
    }, RECHECK_MS)
    // Waiting for the listener must never hold the process open on its own.
    timer.unref?.()

    return () => {
      if (timer !== undefined) {
        clearInterval(timer)
        timer = undefined
      }
      release()
    }
  })
}

/**
 * Name an authority's cookie exactly as the Host does.
 *
 * `requestAudience` keeps the bare authority for plain HTTP and the full origin
 * for TLS, so the name follows the same rule.
 *
 * @param protocol - the listener's protocol, `'http:'` or `'https:'`.
 * @param host - the authority (`host:port`) from the request or the bind.
 * @returns the cookie name, or `undefined` when the authority is unreadable.
 */
function cookieNameOf(protocol, host) {
  if (typeof host !== 'string' || host === '') return undefined
  try {
    const url = new URL(`${protocol}//${host}`)
    const authority = protocol === 'https:' ? url.origin : url.host
    return PREFIX + createHash('sha256').update(authority).digest('base64url')
  } catch {
    return undefined
  }
}

/**
 * Read the authority the listener is bound to, as a fallback for requests that
 * carry no Host header.
 *
 * @param webServer - the live service, used only for its bound origin.
 * @returns `host:port`, or `undefined` when the origin is unreadable.
 */
function boundHost(webServer) {
  try {
    return new URL(webServer.getOrigin()).host
  } catch {
    return undefined
  }
}

/**
 * Read the protocol the listener actually serves, from its own origin.
 *
 * The cookie name keeps the bare authority for plain HTTP and the full origin
 * for TLS, so the protocol has to match the Host's view rather than a guess.
 *
 * @param webServer - the live service.
 * @returns `'http:'` or `'https:'`; plain HTTP when the origin is unreadable.
 */
function originProtocol(webServer) {
  try {
    return new URL(webServer.getOrigin()).protocol
  } catch {
    return 'http:'
  }
}

/**
 * Symbol key holding a response's queued `Set-Cookie` deletions.
 *
 * @type {symbol}
 */
const COOKIES = Symbol('auth-cookie-guard.cookies')

/**
 * Queue `Set-Cookie` deletions until the response commits its headers.
 *
 * The welcome handshake answers with `res.writeHead(303, { 'set-cookie': … })`.
 * Node replaces every existing value of a header named in that object, so a
 * deletion appended beforehand is silently lost. Keeping the lines here and
 * merging them inside this response's own `writeHead` puts them on the same
 * response for all three call shapes — object, flat array, and no headers —
 * instead of depending on a later request to carry the cleanup.
 *
 * @param res - the response being prepared.
 * @param lines - cookie serializations to add.
 */
function armCookies(res, lines) {
  if (lines.length === 0) return
  const state = res[COOKIES] ?? (res[COOKIES] = { lines: [], armed: false })
  state.lines.push(...lines)
  if (state.armed) return
  state.armed = true

  const writeHead = res.writeHead
  res.writeHead = function (statusCode, statusMessage, headers) {
    const pending = state.lines
    let message
    if (typeof statusMessage === 'string') message = statusMessage
    else headers = statusMessage

    if (Array.isArray(headers)) {
      headers = [...headers, ...pending.flatMap((line) => ['set-cookie', line])]
    } else if (headers !== undefined && headers !== null) {
      const copy = {}
      const cookies = []
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === 'set-cookie') cookies.push(...cookieValues(headers[key]))
        else copy[key] = headers[key]
      }
      copy['set-cookie'] = [...cookies, ...pending]
      headers = copy
    } else {
      res.setHeader('set-cookie', [...cookieValues(res.getHeader('set-cookie')), ...pending])
    }

    return message === undefined
      ? writeHead.call(res, statusCode, headers)
      : writeHead.call(res, statusCode, message, headers)
  }
}

/**
 * Normalize one header value to the array form `setHeader` expects.
 *
 * @param value - current `Set-Cookie` value, if any.
 * @returns the value as an array.
 */
function cookieValues(value) {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

/**
 * Clamp a configuration number, falling back when it is not a number.
 *
 * @param value - configured value.
 * @param fallback - value used when configuration is absent or invalid.
 * @param range - inclusive `[min, max]` bounds.
 * @returns a usable integer.
 */
function bounded(value, fallback, range) {
  const number = Number(value)
  if (value === undefined || value === null || !Number.isFinite(number)) return fallback
  return Math.min(range[1], Math.max(range[0], Math.trunc(number)))
}
