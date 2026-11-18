import test from 'node:test';
import assert from 'node:assert/strict';
import worker from './index.js';

const env = { FIREBASE_PROJECT_ID: 'gestaoestoquebagaco', ADMIN_EMAIL: 'endersonerval@gmail.com' };

test('preflight permite apenas os métodos e cabeçalhos esperados', async () => {
  const response = await worker.fetch(new Request('https://example.test', { method: 'OPTIONS' }), env);
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('access-control-allow-methods'), 'POST, OPTIONS');
});

test('não assina pedidos sem sessão ou com token inválido', async () => {
  for (const headers of [{}, { Authorization: 'Bearer token-invalido' }]) {
    const response = await worker.fetch(new Request('https://example.test', { method: 'POST', headers }), env);
    assert.equal(response.status, 401);
    assert.equal((await response.json()).signature, undefined);
  }
});

test('recusa outros métodos', async () => {
  const response = await worker.fetch(new Request('https://example.test'), env);
  assert.equal(response.status, 405);
});
