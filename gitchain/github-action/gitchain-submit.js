/**
 * GitChain GitHub Action script
 *
 * Runs on every git push as a CI step. Reads commit metadata from the
 * GitHub environment, builds + signs the transaction payload, and POSTs
 * it to the team's GitChain node.
 *
 * Dependencies (installed by the action):
 *   tweetnacl     — Ed25519 sign/verify (same algorithm as PyNaCl)
 *
 * Environment variables (from GitHub Secrets):
 *   GITCHAIN_PRIVATE_KEY  — 64-char hex Ed25519 private key
 *   GITCHAIN_NODE_URL     — e.g. http://192.168.1.10:8000
 *
 * GitHub-provided environment variables (automatic):
 *   GITHUB_SHA            — commit hash
 *   GITHUB_ACTOR          — GitHub username of the pusher
 *   GITHUB_REPOSITORY     — org/repo
 *   GITHUB_REF_NAME       — branch name
 */

const nacl = require('tweetnacl');
const { execSync } = require('child_process');
const https = require('https');
const http = require('http');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// 1. Read inputs
// ---------------------------------------------------------------------------

const privateKeyHex = process.env.GITCHAIN_PRIVATE_KEY;
const nodeUrl       = process.env.GITCHAIN_NODE_URL;
const commitHash    = process.env.GITHUB_SHA;
const repo          = process.env.GITHUB_REPOSITORY;
const branch        = process.env.GITHUB_REF_NAME || 'unknown';
const author        = process.env.GITHUB_ACTOR    || 'unknown';
const timestamp     = Math.floor(Date.now() / 1000);

if (!privateKeyHex || !nodeUrl || !commitHash || !repo) {
  console.error('Missing required environment variables.');
  console.error('Required: GITCHAIN_PRIVATE_KEY, GITCHAIN_NODE_URL, GITHUB_SHA, GITHUB_REPOSITORY');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// 2. Get diff summary from git
// ---------------------------------------------------------------------------

let diffSummary = 'unknown';
let diffHash = '';
try {
  const stat = execSync('git show --stat HEAD', { encoding: 'utf8' });
  // Extract the summary line: "3 files changed, 42 insertions(+), 7 deletions(-)"
  const match = stat.match(/(\d+ files? changed.*)/);
  if (match) diffSummary = match[1].trim();
} catch (e) {
  console.warn('Warning: could not get diff summary:', e.message);
}
try {
  const fullDiff = execSync('git show -p HEAD', { encoding: 'utf8' });
  diffHash = crypto.createHash('sha256').update(fullDiff).digest('hex');
} catch (e) {
  console.warn('Warning: could not compute diff hash:', e.message);
}

// ---------------------------------------------------------------------------
// 3. Derive public key from private key
// ---------------------------------------------------------------------------

const privateKeyBytes = Buffer.from(privateKeyHex, 'hex');

// tweetnacl expects a 64-byte seed+pubkey buffer; PyNaCl stores only the 32-byte seed.
// If we only have 32 bytes, generate the full keypair from the seed.
let keyPair;
if (privateKeyBytes.length === 32) {
  keyPair = nacl.sign.keyPair.fromSeed(privateKeyBytes);
} else if (privateKeyBytes.length === 64) {
  keyPair = nacl.sign.keyPair.fromSecretKey(privateKeyBytes);
} else {
  console.error('Invalid private key length:', privateKeyBytes.length);
  process.exit(1);
}

const ownerPubkey = Buffer.from(keyPair.publicKey).toString('hex');

// ---------------------------------------------------------------------------
// 4. Build and hash the payload
// ---------------------------------------------------------------------------

const payloadFields = {
  author:        author,
  branch:        branch,
  commit_hash:   commitHash,
  diff_hash:     diffHash,
  diff_summary:  diffSummary,
  owner_pubkey:  ownerPubkey,
  repo:          repo,
  timestamp:     timestamp,
};

// Deterministic JSON — sorted keys, no spaces.
// Matches Python's json.dumps(sort_keys=True, separators=(',', ':'))
// Timestamp is already an integer from Math.floor, matching Python's int(timestamp) in compute_payload_hash().
const canonicalPayload = JSON.stringify(
  Object.keys(payloadFields).sort().reduce((acc, k) => { acc[k] = payloadFields[k]; return acc; }, {}),
);

const payloadHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex');

// ---------------------------------------------------------------------------
// 5. Sign the payload hash with Ed25519
// ---------------------------------------------------------------------------

// Sign the UTF-8 bytes of the hex hash string (matches signer.py)
// Buffer.from(string) encodes as UTF-8 and is a native Uint8Array subclass —
// avoids tweetnacl-util compatibility issues with checkArrayTypes.
const signature = Buffer.from(
  nacl.sign.detached(Buffer.from(payloadHash), keyPair.secretKey)
).toString('hex');

// ---------------------------------------------------------------------------
// 6. Build the transaction object
// ---------------------------------------------------------------------------

const transaction = {
  commit_hash:  commitHash,
  owner_pubkey: ownerPubkey,
  author:       author,
  repo:         repo,
  branch:       branch,
  timestamp:    timestamp,
  diff_summary: diffSummary,
  diff_hash:    diffHash,
  payload_hash: payloadHash,
  signature:    signature,
};

console.log('GitChain transaction:');
console.log('  commit:', commitHash.slice(0, 12) + '...');
console.log('  repo:  ', repo);
console.log('  branch:', branch);
console.log('  author:', author);

// ---------------------------------------------------------------------------
// 7. POST to node with retry (exponential backoff)
// ---------------------------------------------------------------------------

const MAX_RETRIES = 3;

function post(url, body) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === 'https:' ? https : http;
    const data = JSON.stringify(body);

    const req = transport.request(
      {
        hostname: parsed.hostname,
        port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
        path:     parsed.pathname,
        method:   'POST',
        headers:  {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(data),
        },
      },
      (res) => {
        let responseBody = '';
        res.on('data', chunk => { responseBody += chunk; });
        res.on('end', () => {
          if (res.statusCode === 201 || res.statusCode === 409) {
            // 201 = accepted, 409 = already recorded (both are fine)
            resolve({ status: res.statusCode, body: responseBody });
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${responseBody}`));
          }
        });
      }
    );

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

async function submitWithRetry() {
  const endpoint = nodeUrl.replace(/\/$/, '') + '/transaction';

  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const result = await post(endpoint, transaction);
      if (result.status === 409) {
        console.log('Commit already on-chain — skipping.');
      } else {
        console.log('✓ Transaction accepted by GitChain node.');
      }
      return;
    } catch (err) {
      console.warn(`Attempt ${attempt}/${MAX_RETRIES} failed: ${err.message}`);
      if (attempt < MAX_RETRIES) {
        const delay = Math.pow(2, attempt) * 500;   // 1s, 2s, 4s
        console.log(`Retrying in ${delay}ms...`);
        await new Promise(r => setTimeout(r, delay));
      } else {
        console.error('All retry attempts exhausted. GitChain node may be offline.');
        // Do NOT fail the CI build — contribution recording is best-effort
        // The commit is still pushed to GitHub; it will be recorded when node is back.
        process.exit(0);
      }
    }
  }
}

submitWithRetry();
