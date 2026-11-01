const express = require('express');
const cors = require('cors');
const { createClient } = require('@libsql/client');

const app = express();
app.use(cors());
app.use(express.json());

// Connect to your cloud SQLite database
const db = createClient({
  url: process.env.TURSO_DATABASE_URL,
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Auto-create table if it doesn't exist
async function initDb() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS scores (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      points INTEGER
    )
  `);
}
initDb();

app.get('/api/scores', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM scores');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scores', async (req, res) => {
  try {
    const { name, points } = req.body;
    await db.execute({
      sql: 'INSERT INTO scores (name, points) VALUES (?, ?)',
      args: [name, points]
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = app; // Required for Vercel serverless
