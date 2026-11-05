// tests/e2e/m33b-spike.spec.mjs — Plan 33b Task 1 spike (spec §15).
//
// Proves, before any passkey runtime exists, that Chromium's CDP virtual
// authenticator runs WebAuthn ceremonies against an in-process HTTPS server
// on an `*.e2e.test` host with a throwaway certificate, and records which
// TLS mode works and whether conditional mediation (autofill) resolves.
//
// No zeroauthy code is exercised: the page is a static HTML document served
// by Node's https module. The ceremonies use the documented Auth0 shapes
// (rp.name = rp.id, pubKeyCredParams -8/-7/-257, residentKey required,
// userVerification preferred, attestation none).
//
// TLS modes, tried in order:
//   1. `ignoreHTTPSErrors` only (the shared config's default).
//   2. Chromium launched with `--ignore-certificate-errors-spki-list=<SPKI>`
//      when WebAuthn refuses the first context (SecurityError / not secure).
// The outcome of each mode and of the conditional `get` is printed and
// asserted; the implementation record and D-0062 copy the result.
import {test, expect, chromium} from '@playwright/test';
import {createServer} from 'node:https';
import {execFileSync} from 'node:child_process';
import {mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash, createPublicKey, randomBytes} from 'node:crypto';

const HOST = 'spike.e2e.test';
const RP_ID = HOST;

const PAGE = `<!doctype html><html><head><meta charset="utf-8"><title>m33b spike</title></head>
<body>
<form id="f"><input id="username" name="username" autocomplete="username webauthn" placeholder="Email address"></form>
<button id="create">Create a passkey</button>
<button id="get">Continue with a passkey</button>
<pre id="log"></pre>
<script>
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const bytes = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
const log = (m) => { document.getElementById('log').textContent += m + '\\n'; };
window.spike = {
  async create(challenge, userId) {
    const cred = await navigator.credentials.create({publicKey: {
      challenge: bytes(challenge),
      rp: {id: ${JSON.stringify(RP_ID)}, name: ${JSON.stringify(RP_ID)}},
      user: {id: bytes(userId), name: 'spike@example.com', displayName: 'spike@example.com'},
      pubKeyCredParams: [{type:'public-key', alg:-8},{type:'public-key', alg:-7},{type:'public-key', alg:-257}],
      authenticatorSelection: {residentKey: 'required', userVerification: 'preferred'},
      attestation: 'none', timeout: 60000,
    }});
    const r = cred.response;
    return {id: cred.id, rawId: b64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment ?? null,
      response: {clientDataJSON: b64u(r.clientDataJSON), attestationObject: b64u(r.attestationObject), transports: r.getTransports ? r.getTransports() : null}};
  },
  async get(challenge, mediation) {
    const opts = {publicKey: {challenge: bytes(challenge), rpId: ${JSON.stringify(RP_ID)}, userVerification: 'preferred', timeout: 60000, allowCredentials: []}};
    if (mediation) opts.mediation = mediation;
    const cred = await navigator.credentials.get(opts);
    const r = cred.response;
    return {id: cred.id, rawId: b64u(cred.rawId), type: cred.type, authenticatorAttachment: cred.authenticatorAttachment ?? null,
      response: {clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature), userHandle: r.userHandle ? b64u(r.userHandle) : null}};
  },
  async conditionalAvailable() {
    return !!(window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable && await PublicKeyCredential.isConditionalMediationAvailable());
  },
};
document.getElementById('get').addEventListener('click', () => { window.lastClick = 'get'; });
log('ready');
</script></body></html>`;

function throwawayCert() {
  const dir = mkdtempSync(join(tmpdir(), 'm33b-spike-'));
  const key = join(dir, 'key.pem'), cert = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '2',
    '-subj', `/CN=${HOST}`, '-addext', `subjectAltName=DNS:${HOST}`, '-keyout', key, '-out', cert], {stdio: 'ignore'});
  const pem = readFileSync(cert);
  const spki = createPublicKey(pem).export({type: 'spki', format: 'der'});
  const spkiHash = createHash('sha256').update(spki).digest('base64');
  writeFileSync(join(dir, 'spki.txt'), spkiHash);
  return {key: readFileSync(key), cert: pem, spkiHash, dir};
}

async function startServer(tls) {
  const server = createServer({key: tls.key, cert: tls.cert}, (req, res) => {
    res.writeHead(200, {'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store'});
    res.end(PAGE);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {server, port: server.address().port};
}

function decodeClientData(b64u) {
  return JSON.parse(Buffer.from(b64u.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
}

async function addVirtualAuthenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable', {enableUI: false});
  const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, defaultBackupEligibility: true, defaultBackupState: true,
  }});
  return {cdp, authenticatorId};
}

// Runs create + button get + conditional get on an already-open page.
// Returns a structured result instead of throwing so the caller can record
// which TLS mode worked.
async function runCeremonies(page, origin) {
  const out = {create: null, get: null, conditional: null, errors: {}};
  const {cdp, authenticatorId} = await addVirtualAuthenticator(page);
  await page.goto(`${origin}/`);
  await expect(page.locator('#log')).toContainText('ready');
  const challenge1 = randomBytes(32).toString('base64url');
  const userId = randomBytes(32).toString('base64url');
  try {
    out.create = await page.evaluate(([c, u]) => window.spike.create(c, u), [challenge1, userId]);
  } catch (e) {
    out.errors.create = String(e && e.message || e);
    return out;
  }
  const creds = await cdp.send('WebAuthn.getCredentials', {authenticatorId});
  out.storedCredentials = creds.credentials.length;

  // Button path: a plain modal get with an empty allow list (discoverable).
  const challenge2 = randomBytes(32).toString('base64url');
  await page.click('#get');
  try {
    out.get = await page.evaluate((c) => window.spike.get(c, undefined), challenge2);
  } catch (e) {
    out.errors.get = String(e && e.message || e);
  }

  // Autofill path: conditional mediation on the `username webauthn` input.
  out.conditionalAvailable = await page.evaluate(() => window.spike.conditionalAvailable());
  const challenge3 = randomBytes(32).toString('base64url');
  const conditional = page.evaluate((c) => window.spike.get(c, 'conditional'), challenge3);
  await page.locator('#username').focus();
  await page.keyboard.type('s');
  try {
    out.conditional = await Promise.race([
      conditional,
      new Promise((_, reject) => setTimeout(() => reject(new Error('conditional get did not resolve within 10 s')), 10_000)),
    ]);
  } catch (e) {
    out.errors.conditional = String(e && e.message || e);
    // Leave the pending conditional get to be aborted with the page.
  }
  out.challenges = {create: challenge1, get: challenge2, conditional: challenge3};
  return out;
}

function checkResult(result, origin) {
  expect(result.errors.create, 'create failed: ' + result.errors.create).toBeUndefined();
  expect(result.create.type).toBe('public-key');
  expect(result.create.id).toBe(result.create.rawId);
  const cd = decodeClientData(result.create.response.clientDataJSON);
  expect(cd.type).toBe('webauthn.create');
  expect(cd.origin).toBe(origin);
  expect(cd.challenge).toBe(result.challenges.create);
  expect(cd.crossOrigin ?? false).toBe(false);
  expect(result.storedCredentials).toBe(1);

  expect(result.errors.get, 'button get failed: ' + result.errors.get).toBeUndefined();
  const gd = decodeClientData(result.get.response.clientDataJSON);
  expect(gd.type).toBe('webauthn.get');
  expect(gd.origin).toBe(origin);
  expect(gd.challenge).toBe(result.challenges.get);
  expect(result.get.rawId).toBe(result.create.rawId);
  expect(result.get.response.userHandle).toBeTruthy();
}

test('m33b spike: virtual authenticator create, button get and conditional get over a throwaway certificate', async ({browser}) => {
  test.setTimeout(180_000);
  const tls = throwawayCert();
  const {server, port} = await startServer(tls);
  const origin = `https://${HOST}:${port}`;
  const resolver = `--host-resolver-rules=MAP ${HOST} 127.0.0.1`;
  // The container routes HTTPS through a proxy; the spike host is local.
  const noProxy = '--no-proxy-server';
  const record = {host: HOST, port, spkiHash: tls.spkiHash, modes: {}};
  try {
    // Mode 1: ignoreHTTPSErrors only. The shared config already sets it,
    // but the host mapping needs its own launch, so launch explicitly.
    let worked = null;
    {
      const b = await chromium.launch({headless: true, args: [resolver, noProxy],
        ...(process.env.E2E_CHROMIUM ? {executablePath: process.env.E2E_CHROMIUM} : {})});
      const ctx = await b.newContext({ignoreHTTPSErrors: true});
      const page = await ctx.newPage();
      const result = await runCeremonies(page, origin);
      record.modes.ignoreHTTPSErrors = summarize(result);
      await b.close();
      if (!result.errors.create && !result.errors.get) {
        checkResult(result, origin);
        worked = 'ignoreHTTPSErrors';
      }
    }
    // Mode 2: SPKI pinning, only when mode 1 could not run the ceremonies.
    if (!worked) {
      const b = await chromium.launch({headless: true,
        args: [resolver, noProxy, `--ignore-certificate-errors-spki-list=${tls.spkiHash}`],
        ...(process.env.E2E_CHROMIUM ? {executablePath: process.env.E2E_CHROMIUM} : {})});
      const ctx = await b.newContext();
      const page = await ctx.newPage();
      const result = await runCeremonies(page, origin);
      record.modes.spkiList = summarize(result);
      await b.close();
      checkResult(result, origin);
      worked = 'ignore-certificate-errors-spki-list';
    }
    record.tlsMode = worked;
    const mode = record.modes[worked === 'ignoreHTTPSErrors' ? 'ignoreHTTPSErrors' : 'spkiList'];
    record.conditionalMediation = mode.conditional;
    console.log('M33B_SPIKE_RESULT ' + JSON.stringify(record));
    expect(worked).toBeTruthy();
  } finally {
    server.close();
  }
});

function summarize(result) {
  return {
    create: result.create ? 'ok' : 'failed: ' + result.errors.create,
    buttonGet: result.get ? 'ok' : 'failed: ' + result.errors.get,
    conditionalAvailable: result.conditionalAvailable ?? null,
    conditional: result.conditional ? 'resolved' : 'not resolved: ' + result.errors.conditional,
    attachment: result.create ? result.create.authenticatorAttachment : null,
    transports: result.create ? result.create.response.transports : null,
  };
}
