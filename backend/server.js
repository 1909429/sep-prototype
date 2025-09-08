// server.js
const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');                 // pure-JS bcrypt
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
  headers: { Authorization: `Token ${process.env.INFLUX_TOKEN}` },
  timeout: 15000,
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

/** Health check (bucket-scoped) */
app.get('/api/influx/ping', async (_req, res) => {
  try {
    await influxReady();
    return res.json({ ok: true });
  } catch (e) {
    const status = e.response?.status;
    const data = e.response?.data;
    return res.status(status || 500).json({
      ok: false, status: status || 500, message: e.message, data
    });
  }
});

/** Login -> issue app JWT */
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email & password required' });

    const row = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!row) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = bcrypt.compareSync(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    await influxReady();
    const token = signJwt({ uid: row.id, email: row.email });
    return res.json({ ok: true, token });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

/** Write one point (Line Protocol) */
app.post('/api/write', auth, async (req, res) => {
  try {
    const { measurement = 'demo', tags = { host: 'web' }, fields = { value: 1 }, tsNs } = req.body || {};
    const tagStr = Object.entries(tags)
      .map(([k, v]) => `${k}=${String(v).replace(/[, ]/g, '\\ ')}`).join(',');
    const fieldStr = Object.entries(fields)
      .map(([k, v]) => Number.isInteger(v) ? `${k}=${v}i`
        : (typeof v === 'number' ? `${k}=${v}` : `${k}="${String(v).replace(/"/g, '\\"')}"`))
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

/** Raw Flux query -> CSV */
app.post('/api/query', auth, async (req, res) => {
  try {
    const flux =
      req.body?.flux ||
      `from(bucket:"${process.env.INFLUX_BUCKET}") |> range(start:-15m) |> limit(n:10)`;

    const { data } = await influx.post('/api/v2/query', { query: flux }, {
      params: { org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID },
      headers: { 'Content-Type': 'application/json', Accept: 'application/csv' }
    });
    res.type('text/csv').send(data);
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

/** Minimal verify: org/token/bucket (+ optional user) */
app.post('/api/influx/verify', auth, async (req, res) => {
  try {
    const name = (req.body?.name || '').trim();
    const bucket = (req.body?.bucket || process.env.INFLUX_BUCKET).trim();
    const orgParam = process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID;
    if (!orgParam) return res.status(400).json({ ok:false, error:'INFLUX_ORG_ID (or INFLUX_ORG) is empty' });

    // org by name
    let orgOK = false, orgID = null, orgName = null;
    try {
      const { data } = await influx.get('/api/v2/orgs', { params: { org: orgParam } });
      const found = (data.orgs || [])[0];
      if (found) { orgOK = true; orgID = found.id; orgName = found.name; }
    } catch {}

    // bucket exists
    let bucketExists = false, bucketReadable = false;
    try {
      const params = orgID ? { name: bucket, orgID } : { name: bucket };
      const { data } = await influx.get('/api/v2/buckets', { params });
      const hit = (data.buckets || []).find(b => b.name === bucket);
      if (hit) bucketExists = true;
    } catch {}

    // bucket readable
    try {
      const flux = `from(bucket:"${bucket}") |> range(start:-1m) |> limit(n:1)`;
      await influx.post('/api/v2/query', { query: flux }, {
        params: { org: orgID || orgParam },
        headers: { 'Content-Type': 'application/json' }
      });
      bucketReadable = true;
    } catch {}

    const tokenOK = bucketReadable || orgOK;

    // optional user check
    let userCheck = { existsInOrg: 'unknown', userId: null, reason: null };
    if (name) {
      try {
        const orgX = orgID || orgParam;
        const { data } = await influx.get(`/api/v2/orgs/${orgX}/members`);
        const list = data.users || data.members || [];
        const hit = list.find(u => (u.name || u.user?.name) === name);
        if (hit) userCheck = { existsInOrg: true, userId: (hit.id || hit.user?.id) || null, reason: null };
        else userCheck = { existsInOrg: false, userId: null, reason: null };
      } catch {
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

/* =======================
   Simple JSON data source
   ======================= */

const sj = express.Router();

// very light auth for Simple JSON routes
// Grafana data source -> Custom HTTP Header:  X-API-Key: <SIMPLEJSON_API_KEY>
// If SIMPLEJSON_API_KEY not set, routes are open (dev only).
function authSimple(req, res, next) {
  const keyFromHeader = req.get('X-API-Key') || req.get('x-api-key');
  const bearer = (req.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const key = keyFromHeader || bearer || '';
  if (!process.env.SIMPLEJSON_API_KEY) return next();
  if (key === process.env.SIMPLEJSON_API_KEY) return next();
  return res.status(401).json({ error: 'unauthorized' });
}

sj.get('/', (_req, res) => res.json({ ok: true }));

// /simplejson/search -> list measurements
sj.post('/search', authSimple, async (_req, res) => {
  try {
    const flux = `
import "influxdata/influxdb/schema"
schema.measurements(bucket: "${process.env.INFLUX_BUCKET}")
`.trim();

    const { data } = await influx.post('/api/v2/query', { query: flux }, {
      params: { org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID },
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/csv' }
    });

    const lines = String(data).split('\n').filter(l => l && !l.startsWith('#'));
    if (lines.length === 0) return res.json([]);
    const header = lines[0].split(',');
    const iVal = header.indexOf('_value');
    const names = [...new Set(lines.slice(1).map(l => l.split(',')[iVal]).filter(Boolean))];
    return res.json(names);
  } catch (e) {
    return res.status(500).json({ error: e.message, data: e.response?.data });
  }
});

// /simplejson/query -> timeseries frames
// body: { range:{from,to}, intervalMs, maxDataPoints, targets:[{target,refId}] }
sj.post('/query', authSimple, async (req, res) => {
  try {
    const { range, targets, intervalMs = 60_000, maxDataPoints = 1440 } = req.body || {};
    const fromIso = range?.from || new Date(Date.now() - 3600_000).toISOString();
    const toIso   = range?.to   || new Date().toISOString();
    const everySec = Math.max(1, Math.floor(intervalMs / 1000));

    const series = await Promise.all((targets || []).map(async (t) => {
      const measurement = t.target || t.refId || 'metric';
      const flux = `
from(bucket:"${process.env.INFLUX_BUCKET}")
  |> range(start: time(v: ${JSON.stringify(fromIso)}), stop: time(v: ${JSON.stringify(toIso)}))
  |> filter(fn:(r)=> r._measurement == ${JSON.stringify(measurement)})
  |> aggregateWindow(every: ${everySec}s, fn: mean, createEmpty: false)
  |> keep(columns: ["_time","_value"])
  |> limit(n:${Number(maxDataPoints)})
`.trim();

      const { data } = await influx.post('/api/v2/query', { query: flux }, {
        params: { org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID },
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/csv' }
      });

      const lines = String(data).split('\n').filter(l => l && !l.startsWith('#'));
      if (!lines.length) return { target: measurement, datapoints: [] };
      const header = lines[0].split(',');
      const iTime = header.indexOf('_time');
      const iVal  = header.indexOf('_value');

      const datapoints = lines.slice(1).map(l => {
        const cols = l.split(',');
        const ts = Date.parse(cols[iTime]);
        const v  = Number(cols[iVal]);
        return [Number.isFinite(v) ? v : null, ts];
      }).filter(dp => dp[0] !== null && Number.isFinite(dp[1]));

      return { target: measurement, datapoints };
    }));

    return res.json(series);
  } catch (e) {
    return res.status(500).json({ error: e.message, data: e.response?.data });
  }
});

// optional: satisfy plugin calls if needed
sj.post('/annotations', authSimple, async (_req, res) => res.json([]));
sj.post('/tag-keys',   authSimple, async (_req, res) => res.json([]));
sj.post('/tag-values', authSimple, async (_req, res) => res.json([]));

// mount
app.use('/simplejson', sj);

/* ======================= */

const port = Number(process.env.PORT || 4000); // default 4000 (avoid Grafana 3000)
app.listen(port, () => {
  console.log(`Server running: http://localhost:${port}`);
  console.log('[Influx ENV]', {
    host: process.env.INFLUX_HOST,
    org: process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID,
    bucket: process.env.INFLUX_BUCKET,
    token_len: (process.env.INFLUX_TOKEN || '').length
  });
});
