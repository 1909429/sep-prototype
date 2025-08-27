// init_db.js
const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '.env') });

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database(path.resolve(__dirname, 'app.db'));

// Create table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    influx_user_id TEXT,
    influx_org_id TEXT,
    influx_bucket TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

// Optional: unique index on influx_user_id (SQLite allows multiple NULLs)
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_influx_uid ON users(influx_user_id);`);

// Seed a dev user
const email = 'test@example.com';
const pass = 'password123';
const hash = bcrypt.hashSync(pass, 10);

try {
  const org = process.env.INFLUX_ORG || process.env.INFLUX_ORG_ID || '';
  const bucket = process.env.INFLUX_BUCKET || '';
  const stmt = db.prepare(
    `INSERT INTO users(email, password_hash, influx_org_id, influx_bucket)
     VALUES(?,?,?,?)`
  );
  stmt.run(email, hash, org, bucket);
  console.log('Seed ok:', email, pass);
} catch (e) {
  console.log('Seed skipped (maybe exists).');
}

db.close();
