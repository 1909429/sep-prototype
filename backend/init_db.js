const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('./app.db');
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
(async () => {
  const email = 'test@example.com';
  const pass = 'password123';
  const hash = await bcrypt.hash(pass, 10);
  try {
    db.prepare(`INSERT INTO users(email,password_hash,influx_org_id,influx_bucket)
      VALUES(?,?,?,?)`).run(email, hash, '023ccc973185611d', 'mywebapp_dev');
    console.log('Seed ok:', email, pass);
  } catch (e) {
    console.log('Seed skipped (maybe exists).');
  }
  db.close();
})();