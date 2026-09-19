import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { resolve } from 'node:path';
import test from 'node:test';

const port = 18789;
const baseUrl = `http://127.0.0.1:${port}`;
let server;

async function waitForServer(child) {
  const deadline = Date.now() + 5000;
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });

  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`API завершился раньше времени: ${output}`);
    try {
      const response = await fetch(`${baseUrl}/health`);
      if (response.ok) return;
    } catch {
      // Сервер ещё запускается.
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  }
  throw new Error(`API не запустился: ${output}`);
}

async function login(accountId, password = 'test-password') {
  return fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accountId, password }),
  });
}

test.before(async () => {
  server = spawn(process.execPath, ['api/server.mjs'], {
    cwd: resolve('.'),
    env: {
      ...process.env,
      PORT: String(port),
      OPENAI_API_KEY: 'test-key',
      SESSION_SECRET: 'test-session-secret-with-at-least-32-characters',
      ACCOUNTS_FILE: resolve('test/fixtures/accounts.json'),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForServer(server);
});

test.after(async () => {
  if (!server || server.exitCode !== null) return;
  server.kill('SIGTERM');
  await once(server, 'exit');
});

test('родитель получает только профили своей семьи', async () => {
  const response = await login('test-parent');
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.equal(data.account.familyId, 'family-test');
  assert.equal(data.account.role, 'parent');
  assert.deepEqual(data.account.profiles.map((profile) => profile.key), ['child-a', 'child-b']);

  const me = await fetch(`${baseUrl}/auth/me`, {
    headers: { Authorization: `Bearer ${data.token}` },
  });
  assert.equal(me.status, 200);
});

test('ребёнок получает только собственный профиль', async () => {
  const response = await login('test-child');
  assert.equal(response.status, 200);
  const data = await response.json();
  assert.deepEqual(data.account.profiles.map((profile) => profile.key), ['child-a']);
});

test('неверный пароль отклоняется', async () => {
  const response = await login('test-parent', 'wrong-password');
  assert.equal(response.status, 401);
});

test('родитель не может отправить сообщение от неизвестного профиля', async () => {
  const loginResponse = await login('test-parent');
  const { token } = await loginResponse.json();
  const response = await fetch(`${baseUrl}/chat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      profile: { key: 'foreign-child', name: 'Чужой профиль', grade: 6 },
      messages: [{ role: 'user', content: 'Помоги с задачей' }],
    }),
  });
  assert.equal(response.status, 400);
});
