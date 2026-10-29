// Executes only inside the disposable runner on home-secrets-sync-dev_default.
// Every credential and item here is synthetic. Never print response bodies on failure.
import assert from 'node:assert/strict';
import { createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes, randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

assert.equal(process.env.DEVELOPMENT_FIXTURES_ONLY, 'true');
const state = JSON.parse(readFileSync(0, 'utf8'));
const base = 'http://infisical:8080';
const vw = process.env.DEV_VAULTWARDEN_URL;
assert.match(vw, /^https:\/\/\d+\.\d+\.\d+\.\d+:8443$/);
const password = 'Development-fixture-master-password-2026!';
const email = `sync-${randomUUID()}@secrets-sync.invalid`;
const folder = `/sync-test-${randomUUID()}`;

async function api(origin, path, body, token = state.token, method = 'POST', expected = 200) {
  const response = await fetch(origin + path, {
    // spawnSync intentionally blocks this fixture's event loop during CLI runs;
    // close HTTP connections so idle pooled sockets cannot expire unnoticed.
    method, headers: { Accept: 'application/json', 'Content-Type': 'application/json', Connection: 'close', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(30000),
  });
  assert.equal(response.status, expected, `${method} ${path}: unexpected HTTP status (body suppressed)`);
  if (expected === 403) return;
  return response.json();
}

function encrypt(value, key) {
  const iv = randomBytes(16), cipher = createCipheriv('aes-256-cbc', key.subarray(0, 32), iv);
  const ciphertext = Buffer.concat([cipher.update(value), cipher.final()]);
  const mac = createHmac('sha256', key.subarray(32)).update(Buffer.concat([iv, ciphertext])).digest();
  return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${mac.toString('base64')}`;
}
const masterKey = pbkdf2Sync(password, email, 600000, 32, 'sha256');
const hash = pbkdf2Sync(masterKey, password, 1, 32, 'sha256').toString('base64');
const expand = info => createHmac('sha256', masterKey).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
const userKey = randomBytes(64);
const rsa = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'der' }, privateKeyEncoding: { type: 'pkcs8', format: 'der' } });
const verification = await api(vw, '/identity/accounts/register/send-verification-email', { email, name: 'Sync integration fixture' }, null);
await api(vw, '/identity/accounts/register/finish', {
  email, emailVerificationToken: verification, masterPasswordHash: hash,
  key: encrypt(userKey, Buffer.concat([expand('enc'), expand('mac')])), kdf: 0, kdfIterations: 600000,
  keys: { publicKey: rsa.publicKey.toString('base64'), encryptedPrivateKey: encrypt(rsa.privateKey, userKey) },
}, null);
const login = await fetch(`${vw}/identity/connect/token`, {
  method: 'POST', body: new URLSearchParams({ grant_type: 'password', username: email, password: hash, scope: 'api offline_access', client_id: 'cli', deviceType: '8', deviceIdentifier: randomUUID(), deviceName: 'sync-integration-test' }),
});
assert.equal(login.status, 200, 'Synthetic Vaultwarden password login failed');
const jwt = await login.json();
const profile = await api(vw, '/api/accounts/profile', undefined, jwt.access_token, 'GET');
const key = await api(vw, '/api/accounts/api-key', { masterPasswordHash: hash }, jwt.access_token);
assert.equal(typeof key.apiKey, 'string');

async function identity(role) {
  const { identity } = await api(base, '/api/v1/identities', { name: `sync-test-${role}-${randomUUID()}`, organizationId: state.orgId, role: 'member' });
  await api(base, `/api/v1/projects/${state.projectId}/identity-memberships/${identity.id}`, { role });
  const { identityUniversalAuth: auth } = await api(base, `/api/v1/auth/universal-auth/identities/${identity.id}`, { accessTokenTTL: 900, accessTokenMaxTTL: 900 });
  const secret = await api(base, `/api/v1/auth/universal-auth/identities/${identity.id}/client-secrets`, { description: 'Disposable integration fixture' });
  assert.equal(typeof auth.clientId, 'string');
  assert.equal(typeof secret.clientSecret, 'string');
  return { clientId: auth.clientId, clientSecret: secret.clientSecret };
}
const writer = await identity('member');
const viewer = await identity('viewer');
await api(base, '/api/v1/folders', { workspaceId: state.projectId, environment: 'production', path: '/', name: folder.slice(1) });

const bwEnv = { PATH: process.env.PATH, HOME: '/scratch', TMPDIR: '/scratch', BITWARDENCLI_APPDATA_DIR: '/scratch/owner', BW_CLIENTID: `user.${profile.id}`, BW_CLIENTSECRET: key.apiKey, BW_PASSWORD: password, NODE_EXTRA_CA_CERTS: '/dev-ca.crt', BW_NOINTERACTION: 'true' };
function bw(args, input) {
  const result = spawnSync('/usr/local/bin/bw', args, { env: bwEnv, input, encoding: 'utf8', timeout: 90000, maxBuffer: 8 * 1024 * 1024 });
  assert.equal(result.status, 0, `bw ${args[0]} failed: code=${result.error?.code ?? '-'} signal=${result.signal ?? '-'} (output suppressed)`);
  return result.stdout.trim();
}
const config = {
  sourceID: 'integration-fixture', vaultwarden: { server: vw, runtimeDir: '/scratch', binary: '/usr/local/bin/bw' },
  destinations: { 'infisical-dev': { url: base, allowInsecureHTTP: true, projects: { 'backend-secrets': { id: state.projectId, environments: ['production'], pathPrefixes: [folder] } } } },
};
writeFileSync('/scratch/config.json', JSON.stringify(config), { mode: 0o600 });
const syncEnv = { PATH: process.env.PATH, NODE_EXTRA_CA_CERTS: '/dev-ca.crt', BW_CLIENTID: bwEnv.BW_CLIENTID, BW_CLIENTSECRET: key.apiKey, BW_PASSWORD: password, INFISICAL_CLIENT_ID: writer.clientId, INFISICAL_CLIENT_SECRET: writer.clientSecret };
function sync(apply, failure = false, credentials = writer) {
  const result = spawnSync('/usr/local/bin/home-secrets-sync', ['-config', '/scratch/config.json', ...(apply ? ['-apply'] : [])], {
    env: { ...syncEnv, INFISICAL_CLIENT_ID: credentials.clientId, INFISICAL_CLIENT_SECRET: credentials.clientSecret }, encoding: 'utf8', timeout: 300000,
  });
  for (const sensitive of [key.apiKey, password, writer.clientSecret, viewer.clientSecret, 'Synthetic-password-v1!', 'Synthetic-password-v2!', 'synthetic-user']) {
    assert.ok(!`${result.stdout}${result.stderr}`.includes(sensitive), 'Sensitive fixture leaked to sync output');
  }
  if (failure) { assert.equal(result.status, 1, 'Expected synchronization refusal'); return result.stderr; }
  assert.equal(result.status, 0, `Synchronization failed: ${result.stderr}`);
  return JSON.parse(result.stdout);
}
const query = new URLSearchParams({ projectId: state.projectId, environment: 'production', secretPath: folder, type: 'shared', expandSecretReferences: 'false', includeImports: 'false' });
async function getSecret(name, token = state.token) { return (await api(base, `/api/v4/secrets/${name}?${query}`, undefined, token, 'GET')).secret; }
function meta(item, name, value) { const f = item.fields.find(f => f.name === name); if (f) f.value = value; else item.fields.push({ name, value, type: 0 }); }
function edit(item) {
  // Keep the server's updated revisionDate for the next fixture edit.
  Object.assign(item, JSON.parse(bw(['edit', 'item', item.id, Buffer.from(JSON.stringify(item)).toString('base64')])));
}
function fixture() { return {
  type: 1, name: 'Synthetic synchronizer integration', login: { username: 'synthetic-user', password: 'Synthetic-password-v1!', uris: [{ uri: 'https://aiga.example.invalid/login' }] },
  fields: [
    ['sync.enabled','true'], ['sync.destination','infisical-dev'], ['sync.project','backend-secrets'], ['sync.path',folder],
    ['sync.export.AIGA_URL','login.uris[0].uri'], ['sync.export.AIGA_USERNAME','login.username'], ['sync.export.AIGA_PASSWORD','login.password'],
  ].map(([name,value])=>({ name,value,type:0 })),
}; }

bw(['config', 'server', vw]); bw(['login', '--apikey']);
bwEnv.BW_SESSION = bw(['unlock', '--passwordenv', 'BW_PASSWORD', '--raw']);
try {
  let item = JSON.parse(bw(['create', 'item', Buffer.from(JSON.stringify(fixture())).toString('base64')]));
  let report = sync(false);
  assert.equal(report.create, 3); assert.equal(report.written, 0);
  console.log('PASS: API-key login/unlock and dry-run of three exports.');
  // Readonly identity may plan, but the server must reject actual writes.
  const viewerFailure = sync(true, true, viewer);
  assert.match(viewerFailure, /HTTP 403/);
  assert.equal(sync(false).create, 3, 'Viewer unexpectedly created secrets');
  report = sync(true); assert.equal(report.written, 3);
  for (const [name,value] of [['AIGA_URL','https://aiga.example.invalid/login'],['AIGA_USERNAME','synthetic-user'],['AIGA_PASSWORD','Synthetic-password-v1!']]) {
    assert.equal((await getSecret(name)).secretValue, value, 'Export differs from Vaultwarden');
  }
  const first = await getSecret('AIGA_PASSWORD');
  console.log('PASS: Viewer write denied; writer created URL, username and password.');
  report = sync(true); assert.equal(report.unchanged, 3); assert.equal(report.written, 0);
  assert.equal((await getSecret('AIGA_PASSWORD')).version, first.version, 'No-op produced a new secret version');
  item.login.password = 'Synthetic-password-v2!'; edit(item);
  report = sync(true); assert.equal(report.update, 1); assert.equal(report.written, 1);
  assert.equal((await getSecret('AIGA_PASSWORD')).secretValue, 'Synthetic-password-v2!');
  assert.equal((await getSecret('AIGA_PASSWORD')).version, first.version + 1);
  console.log('PASS: unchanged values keep their version; rotation updates one secret.');
  const duplicate = structuredClone(item); delete duplicate.id; duplicate.name = 'Synthetic collision';
  const collision = JSON.parse(bw(['create', 'item', Buffer.from(JSON.stringify(duplicate)).toString('base64')]));
  assert.match(sync(true, true), /multiple exports/);
  meta(collision, 'sync.enabled', 'false'); edit(collision);
  const before = (await getSecret('AIGA_PASSWORD')).version;
  const saved = item.login.password; delete item.login.password; edit(item);
  assert.match(sync(true, true), /missing/);
  assert.equal((await getSecret('AIGA_PASSWORD')).version, before, 'Validation failure changed destination');
  item.login.password = saved; meta(item, 'sync.destination', 'not-allowed'); edit(item);
  assert.match(sync(true, true), /destination is not configured/);
  meta(item, 'sync.destination', 'infisical-dev'); edit(item);
  // Existing unrelated destination secret is never silently adopted.
  await api(base, '/api/v4/secrets/AIGA_PASSWORD', { projectId: state.projectId, environment: 'production', secretPath: folder, secretComment: 'manual-fixture-owner' }, state.token, 'PATCH');
  assert.match(sync(true, true), /not owned/);
  console.log('PASS: collision, missing source, unknown destination and ownership conflict refused.');
  await api(base, '/api/v4/secrets/AIGA_PASSWORD', { projectId: state.projectId, environment: 'production', secretPath: folder, secretComment: first.secretComment }, state.token, 'PATCH');
  meta(item, 'sync.enabled', 'false'); edit(item);
  report = sync(true); assert.equal(report.exports, 0);
  assert.equal((await getSecret('AIGA_PASSWORD')).secretValue, saved, 'Disabling an item deleted its destination');
  const viewerLogin = await api(base, '/api/v1/auth/universal-auth/login', viewer, null);
  assert.equal((await getSecret('AIGA_PASSWORD', viewerLogin.accessToken)).secretValue, saved);
  console.log('PASS: real API-key/unlock, URL/username/password, default production, dry-run, Viewer read/write denial, create, rotation, unchanged versions, collision, missing source, allowlist, ownership, no deletion, output redaction.');
} finally {
  bw(['logout']);
}
