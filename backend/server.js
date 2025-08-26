// server.js
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');                 // Pure-JS bcrypt to avoid native build issues
const Database = require('better-sqlite3');
const path = require('path');

// Always load the .env that lives next to this file
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const app = express();
app.use(express.json());

// --- SQLite (local auth DB) ---
const dbPath = path.resolve(__dirname, 'app.db');
const db = new Database(dbPath);

// --- Influx REST client ---
const influx = axios.create({
  baseURL: process.env.INFLUX_HOST,
  headers: { Authorization: `Token ${process.env.INFLUX_TOKEN}` }
});

/**
 * Minimal, bucket-scoped health check.
 * Works with read/write tokens limited to a specific bucket.
 * Throws if unreachable or unauthorized.
 */
async function influxReady() {
  const orgParam = process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID;
  if (!process.env.INFLUX_TOKEN) throw new Error('INFLUX_TOKEN is empty');
  if (!orgParam) throw new Error('INFLUX_ORG_ID (or INFLUX_ORG) is empty');
  if (!process.env.INFLUX_BUCKET) throw new Error('INFLUX_BUCKET is empty');

  const flux = `from(bucket:"${process.env.INFLUX_BUCKET}") |> range(start:-1m) |> limit(n:1)`;
  await influx.post('/api/v2/query', { query: flux }, {
    params: { org: orgParam },
    headers: { 'Content-Type': 'application/json' }
  });
}

// --- JWT helpers ---
function signJwt(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '2h' });
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing bearer token' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// --- Endpoints ---

/**
 * Health check:
 * Validates Influx connectivity/permissions using a bucket-scoped query.
 * Returns detailed error info if it fails.
 */
app.get('/api/influx/ping', async (_req, res) => {
  try {
    await influxReady();
    return res.json({ ok: true });
  } catch (e) {
    const status = e.response?.status;
    const data = e.response?.data;
    return res.status(status || 500).json({
      ok: false,
      status: status || 500,
      message: e.message,
      data
    });
  }
});

/**
 * Login:
 * 1) Validate email/password against local SQLite users table.
 * 2) Probe Influx connectivity/permissions.
 * 3) Return an app JWT (never expose the Influx token to clients).
 */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const row = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    await influxReady(); // Optional: replace with stricter checks if needed
    const token = signJwt({ uid: row.id, email: row.email });
    return res.json({ ok: true, token });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

/**
 * Write a single data point to Influx (requires login).
 * Body example:
 * {
 *   "measurement": "demo",
 *   "tags": {"host": "web"},
 *   "fields": {"value": 2},
 *   "tsNs": 1710000000000000000
 * }
 */
app.post('/api/write', auth, async (req, res) => {
  try {
    const { measurement = 'demo', tags = { host: 'web' }, fields = { value: 1 }, tsNs } = req.body || {};

    // Build Line Protocol tags (escape commas/spaces)
    const tagStr = Object.entries(tags)
      .map(([k, v]) => `${k}=${String(v).replace(/[, ]/g, '\\ ')}`)
      .join(',');

    // Build fields: integers need trailing 'i'; strings quoted
    const fieldStr = Object.entries(fields)
      .map(([k, v]) => {
        if (Number.isInteger(v)) return `${k}=${v}i`;
        if (typeof v === 'number') return `${k}=${v}`;
        return `${k}="${String(v).replace(/"/g, '\\"')}"`;
      })
      .join(',');

    const line = `${measurement}${tagStr ? ',' + tagStr : ''} ${fieldStr} ${tsNs || Date.now() * 1_000_000}`;

    await influx.post('/api/v2/write', line, {
      params: {
        org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID,
        bucket: process.env.INFLUX_BUCKET,
        precision: 'ns'
      },
      headers: { 'Content-Type': 'text/plain' }
    });

    return res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

/**
 * Query Influx with a Flux script (requires login).
 * If no Flux is provided, runs a simple default query.
 * Returns CSV for easy inspection.
 */
app.post('/api/query', auth, async (req, res) => {
  try {
    const flux =
      req.body?.flux ||
      `from(bucket:"${process.env.INFLUX_BUCKET}") |> range(start:-15m) |> limit(n:10)`;

    const { data } = await influx.post(
      '/api/v2/query',
      { query: flux },
      {
        params: { org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID },
        headers: { 'Content-Type': 'application/json', Accept: 'application/csv' }
      }
    );

    res.type('text/csv').send(data);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

/**
 * Minimal verification endpoint:
 * Verifies org/token/bucket and (optionally) whether a given user exists in the org.
 * Body:
 * {
 *   "name": "user@domain.com",   // optional: Influx user name (Cloud often uses the email)
 *   "bucket": "mywebapp_dev"     // optional: defaults to INFLUX_BUCKET
 * }
 * Returns a JSON summary of checks.
 */
app.post('/api/influx/verify', auth, async (req, res) => {
  try {
    const name = (req.body?.name || '').trim();     // optional user name/email
    const bucket = (req.body?.bucket || process.env.INFLUX_BUCKET).trim();

    // Determine org parameter (prefer org name if provided, else org ID)
    const orgParam = process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID;
    if (!orgParam) return res.status(400).json({ ok:false, error:'INFLUX_ORG_ID (or INFLUX_ORG) is empty' });

    // A) Check org exists via /orgs?org=
    let orgOK = false, orgID = null, orgName = null;
    try {
      const { data } = await influx.get('/api/v2/orgs', { params: { org: orgParam } });
      const found = (data.orgs || [])[0];
      if (found) { orgOK = true; orgID = found.id; orgName = found.name; }
    } catch (_) {}

    // B) Check bucket exists (via /buckets) and is readable (via a tiny Flux query)
    let bucketExists = false, bucketReadable = false;
    try {
      const params = orgID ? { name: bucket, orgID } : { name: bucket };
      const { data } = await influx.get('/api/v2/buckets', { params });
      const hit = (data.buckets || []).find(b => b.name === bucket);
      if (hit) bucketExists = true;
    } catch (_) {}

    try {
      const flux = `from(bucket:"${bucket}") |> range(start:-1m) |> limit(n:1)`;
      await influx.post('/api/v2/query', { query: flux }, {
        params: { org: orgID || orgParam },
        headers: { 'Content-Type': 'application/json' }
      });
      bucketReadable = true;
    } catch (_) {
      // If this fails, keep bucketReadable=false; the token may not have read perms for this bucket.
    }

    // C) Token validity heuristic:
    // If we can read the bucket or at least resolve the org, consider the token OK.
    const tokenOK = bucketReadable || orgOK;

    // D) Optional: Check if the user exists in the org (may require additional permissions).
    let userCheck = { existsInOrg: 'unknown', userId: null, reason: null };
    if (name) {
      try {
        // Prefer org members endpoint
        const orgX = orgID || orgParam;
        const { data } = await influx.get(`/api/v2/orgs/${orgX}/members`);
        const list = data.users || data.members || [];
        const hit = list.find(u => (u.name || u.user?.name) === name);
        if (hit) userCheck = { existsInOrg: true, userId: (hit.id || hit.user?.id) || null, reason: null };
        else userCheck = { existsInOrg: false, userId: null, reason: null };
      } catch {
        // Fallback to /users if /members is not permitted by the token
        try {
          const { data } = await influx.get('/api/v2/users');
          const hit = (data.users || []).find(u => u.name === name);
          if (hit) userCheck = { existsInOrg: true, userId: hit.id, reason: 'found via /users' };
          else userCheck = { existsInOrg: false, userId: null, reason: 'not found via /users' };
        } catch {
          userCheck = { existsInOrg: 'unknown', userId: null, reason: 'insufficient_permissions' };
        }
      }
    }

    return res.json({
      ok: true,
      org: { checked: true, orgOK, orgID, orgName },
      token: { tokenOK },
      bucket: { name: bucket, bucketExists, bucketReadable },
      user: userCheck
    });
  } catch (e) {
    const status = e.response?.status || 500;
    return res.status(status).json({ ok:false, error: e.message, data: e.response?.data });
  }
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  // Print minimal, non-sensitive env info to help debugging
  console.log(`Server running: http://localhost:${port}`);
  console.log('[Influx ENV]', {
    host: process.env.INFLUX_HOST,
    org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID,
    bucket: process.env.INFLUX_BUCKET,
    token_len: (process.env.INFLUX_TOKEN || '').length
  });
});
