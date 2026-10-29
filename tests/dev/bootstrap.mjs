// Synthetic development data only. Fixed URLs prohibit targeting production.
import { createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import assert from 'node:assert/strict';

assert.equal(process.env.DEVELOPMENT_FIXTURES_ONLY, 'true');
const stateFile = '/scratch/dev-bootstrap.json';
const email = 'owner@secrets-sync.invalid';
const password = 'Development-fixture-master-password-2026!';

async function api(base, path, body, token, method = 'POST') {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: { Accept: 'application/json', 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(30000),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} returned ${res.status}: ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : {};
}

function encrypt(value, key) {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
  const mac = createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, ciphertext])).digest();
  return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`;
}

// Bitwarden stretches its master key using HKDF-expand without an extract step.
function expand(key, info) {
  return createHmac('sha256', key).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
}

if (!existsSync(stateFile)) {
  const masterKey = pbkdf2Sync(password, email, 600000, 32, 'sha256');
  const passwordHash = pbkdf2Sync(masterKey, password, 1, 32, 'sha256').toString('base64');
  const stretched = Buffer.concat([expand(masterKey, 'enc'), expand(masterKey, 'mac')]);
  const userKey = randomBytes(64);
  const rsa = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const verificationToken = await api('https://vaultwarden:8443', '/identity/accounts/register/send-verification-email', {
    email, name: 'Synthetic Vaultwarden Owner',
  });
  assert.equal(typeof verificationToken, 'string');
  await api('https://vaultwarden:8443', '/identity/accounts/register/finish', {
    email, emailVerificationToken: verificationToken, masterPasswordHash: passwordHash,
    key: encrypt(userKey, stretched), kdf: 0, kdfIterations: 600000,
    keys: { publicKey: rsa.publicKey.toString('base64'), encryptedPrivateKey: encrypt(rsa.privateKey, userKey) },
  });
  const result = spawnSync('infisical', [
    'bootstrap', '--domain=http://127.0.0.1:8080', `--email=${email}`,
    `--password=${password}`, '--organization=homelab-dev', '--output=json',
  ], { encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024 });
  if (result.status !== 0 || !result.stdout.trim()) throw new Error('Development Infisical bootstrap CLI failed');
  const bootstrap = JSON.parse(result.stdout);
  const identity = bootstrap.identity ?? bootstrap.Identity;
  const credentials = identity?.credentials ?? identity?.Credentials;
  const token = credentials?.token ?? credentials?.Token;
  assert.equal(typeof token, 'string', 'Bootstrap must return a development identity token');
  const organization = bootstrap.organization ?? bootstrap.Organization;
  const orgId = organization?.id ?? organization?.Id ?? organization?.ID;
  assert.equal(typeof orgId, 'string', 'Bootstrap must return the development organization ID');
  writeFileSync(stateFile, JSON.stringify({ token, orgId, orgSlug: organization.slug, projectId: null, envReady: false }), { mode: 0o600 });
}

const state = JSON.parse(readFileSync(stateFile, 'utf8'));
if (!state.projectId) {
  const projectResponse = await api('http://127.0.0.1:8080', '/api/v2/workspace', {
    projectName: 'backend-secrets', slug: 'backend-secrets', organizationSlug: state.orgSlug, type: 'secret-manager',
  }, state.token);
  const project = projectResponse.project ?? projectResponse.workspace ?? projectResponse;
  const projectId = project.id;
  assert.equal(typeof projectId, 'string', 'Development project must have an ID');
  state.projectId = projectId;
  writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
}
if (!state.envReady) {
  await api('http://127.0.0.1:8080', `/api/v1/workspace/${state.projectId}/environments`, {
    name: 'Sync Production', slug: 'production', position: 4,
  }, state.token);
  state.envReady = true;
  writeFileSync(stateFile, JSON.stringify(state), { mode: 0o600 });
}

const args = ['--domain=http://127.0.0.1:8080', `--projectId=${state.projectId}`, '--env=production', '--path=/'];
const childEnv = { ...process.env, INFISICAL_TOKEN: state.token };
const setResult = spawnSync('infisical', ['secrets', 'set', 'DEV_PROBE=synthetic-roundtrip', ...args], {
  env: childEnv, encoding: 'utf8', timeout: 30000,
});
if (setResult.status !== 0) throw new Error(`Development secret creation failed (exit ${setResult.status})`);
const getResult = spawnSync('infisical', ['secrets', 'get', 'DEV_PROBE', '--plain', ...args], {
  env: childEnv, encoding: 'utf8', timeout: 30000,
});
assert.equal(getResult.status, 0, 'Development secret read must succeed');
assert.equal(getResult.stdout.trim(), 'synthetic-roundtrip');
console.log('Development Infisical bootstrapped; project/environment ready; secret write/read verified.');
console.log('Synthetic Vaultwarden account registered; ready for official bw login.');
