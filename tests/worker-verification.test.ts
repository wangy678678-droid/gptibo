import assert from 'node:assert/strict'
import test from 'node:test'
import worker from '../worker/index.ts'
import type { Env } from '../worker/platform.ts'
import { generateTotpSecret } from '../worker/totp.ts'

function environment(): Env {
  return {
    ADMIN_USERNAME: 'tester',
    ADMIN_EMAIL: 'admin@example.test',
    ADMIN_TOTP_SECRET: generateTotpSecret(),
    API_LIMITER: { limit: async () => ({ success: true }) },
    EXPENSIVE_LIMITER: { limit: async () => ({ success: true }) },
    INTEREST_DB: { prepare() { throw new Error('Unexpected database access') } },
  } as unknown as Env
}

test('shared login and checkout can read Worker verification configuration without an order or session', async () => {
  const env = environment()
  for (const query of ['', '?purpose=auth']) {
    const response = await worker.fetch(new Request('https://shop.example.invalid/api/orders/verification' + query), env)
    assert.equal(response.status, 200)
    assert.deepEqual(await response.json(), { enabled: false })
    assert.equal(response.headers.get('Cache-Control'), 'no-store')
    assert.equal(response.headers.get('Set-Cookie'), null)
  }
  const protectedResponse = await worker.fetch(new Request('https://shop.example.invalid/api/admin/orders'), env)
  assert.equal(protectedResponse.status, 401)
})

test('Worker verification configuration remains subject to API rate limits', async () => {
  const env = environment()
  env.API_LIMITER.limit = async () => ({ success: false })
  const response = await worker.fetch(new Request('https://shop.example.invalid/api/orders/verification?purpose=auth'), env)
  assert.equal(response.status, 429)
  assert.equal(response.headers.get('Retry-After'), '60')
})
