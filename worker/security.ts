/** Applies to Worker responses; static asset headers are in public/_headers. */
export function secureResponse(request: Request, response: Response): Response {
  const headers = new Headers(response.headers)
  headers.set('X-Content-Type-Options', 'nosniff')
  headers.set('X-Frame-Options', 'DENY')
  headers.set('Referrer-Policy', 'no-referrer')
  headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')
  if (new URL(request.url).protocol === 'https:') headers.set('Strict-Transport-Security', 'max-age=15552000')
  if (new URL(request.url).pathname.startsWith('/api/')) {
    headers.set('Cache-Control', 'no-store')
    headers.set('Content-Security-Policy', "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers })
}

export function requireSecureTransport(request: Request): Response | null {
  const url = new URL(request.url)
  if (url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) return null
  // Never replay a plaintext credential/payment body via an HTTP redirect.
  if (!['GET', 'HEAD'].includes(request.method)) return Response.json({ error: '请通过 HTTPS 安全连接访问本站。' }, { status: 403 })
  url.protocol = 'https:'
  return new Response(null, { status: 308, headers: { Location: url.href } })
}

/** Keep deployment files and source maps out of the SPA fallback, even if a
 * future build accidentally copies one into the asset directory. */
export function rejectPrivatePath(request: Request): Response | null {
  let path: string
  try { path = decodeURIComponent(new URL(request.url).pathname).replaceAll('\\', '/').toLowerCase() }
  catch { path = '/.invalid-path' }
  const hidden = path.split('/').some(part => part.startsWith('.') && part !== '.well-known')
  const source = /^\/(?:worker|src|services|migrations|scripts|tests|emails)(?:\/|$)/.test(path)
  const config = /^\/(?:package(?:-lock)?\.json|wrangler(?:\.[^/]*)?|tsconfig[^/]*|vite\.config\.[^/]*|agents\.md)$/.test(path)
  if (!hidden && !source && !config && !/\.(?:map|sql|sqlite|db|pem|key|p12|pfx)$/.test(path)) return null
  return new Response('Not found', { status: 404, headers: {
    'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
  } })
}
