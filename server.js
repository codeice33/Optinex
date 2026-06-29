require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const { MongoClient } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;
const mongoUri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB || 'optinex';

let client;
let dashboardStates;
let users;

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

function normalizeKey(username, country) {
  return {
    username: String(username || '').trim().toLowerCase(),
    country: String(country || 'Nigeria').trim().toLowerCase()
  };
}

async function getCollection() {
  if (!mongoUri) return null;
  if (!client) {
    client = new MongoClient(mongoUri);
    await client.connect();
    const db = client.db(dbName);
    dashboardStates = db.collection('dashboardStates');
    users = db.collection('users');
    await dashboardStates.createIndex({ username: 1, country: 1 }, { unique: true });
    await users.createIndex({ username: 1 }, { unique: true });
    await users.createIndex({ email: 1 }, { unique: true });
  }
  return dashboardStates;
}

async function getUsersCollection() {
  await getCollection();
  return users || null;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

app.get('/api/health', async (req, res) => {
  const collection = await getCollection().catch(() => null);
  res.json({
    ok: true,
    database: collection ? 'connected' : 'not_configured'
  });
});

app.get('/api/dashboard/state', async (req, res) => {
  const collection = await getCollection().catch(() => null);
  if (!collection) {
    res.json({ found: false, database: 'not_configured' });
    return;
  }

  const key = normalizeKey(req.query.username, req.query.country);
  if (!key.username) {
    res.status(400).json({ error: 'username is required' });
    return;
  }

  const state = await collection.findOne(key, { projection: { _id: 0 } });
  res.json(state ? { found: true, ...state } : { found: false });
});

app.post('/api/register', async (req, res) => {
  const collection = await getUsersCollection().catch(() => null);
  if (!collection) {
    res.status(503).json({ error: 'database not configured' });
    return;
  }

  const username = String(req.body.username || '').trim().toLowerCase();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const country = String(req.body.country || 'Nigeria').trim();

  if (!username || !email || !password) {
    res.status(400).json({ error: 'username, email, and password are required' });
    return;
  }

  const existing = await collection.findOne({ $or: [{ username }, { email }] });
  if (existing) {
    res.status(409).json({ error: 'username or email already exists' });
    return;
  }

  const passwordData = hashPassword(password);
  const user = {
    fullName: String(req.body.fullname || '').trim(),
    username,
    email,
    phoneNumber: String(req.body.phoneNumber || '').trim(),
    country,
    refUsername: String(req.body.refUsername || '').trim().toLowerCase(),
    planType: String(req.body.planType || 'plan_a'),
    passwordHash: passwordData.hash,
    passwordSalt: passwordData.salt,
    createdAt: new Date(),
    updatedAt: new Date()
  };

  await collection.insertOne(user);
  res.status(201).json({ ok: true, user: { username, email, country } });
});

app.post('/api/dashboard/state', async (req, res) => {
  const collection = await getCollection().catch(() => null);
  if (!collection) {
    res.json({ ok: true, database: 'not_configured' });
    return;
  }

  const key = normalizeKey(req.body.username, req.body.country);
  if (!key.username) {
    res.status(400).json({ error: 'username is required' });
    return;
  }

  const existing = await collection.findOne(key);
  const allowClientActivation = process.env.ALLOW_CLIENT_ACTIVATION === 'true';
  const state = {
    ...key,
    name: String(req.body.name || req.body.username || ''),
    activated: Boolean(existing?.activated) || (allowClientActivation && Boolean(req.body.activated)),
    activationRequested: Boolean(req.body.activationRequested) || Boolean(req.body.activated) || Boolean(existing?.activationRequested),
    activeFeatures: Array.isArray(req.body.activeFeatures) ? req.body.activeFeatures : [],
    taskCompleted: Boolean(req.body.taskCompleted),
    taskCompletedDate: String(req.body.taskCompletedDate || ''),
    currency: String(req.body.currency || 'NGN'),
    updatedAt: new Date()
  };

  await collection.updateOne(key, { $set: state, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
  res.json({ ok: true, database: 'connected' });
});

app.post('/api/admin/activate', async (req, res) => {
  if (!process.env.ADMIN_TOKEN || req.headers.authorization !== `Bearer ${process.env.ADMIN_TOKEN}`) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  const collection = await getCollection().catch(() => null);
  if (!collection) {
    res.status(503).json({ error: 'database not configured' });
    return;
  }

  const key = normalizeKey(req.body.username, req.body.country);
  if (!key.username) {
    res.status(400).json({ error: 'username is required' });
    return;
  }

  await collection.updateOne(
    key,
    {
      $set: {
        ...key,
        activated: true,
        activationRequested: false,
        activatedAt: new Date(),
        updatedAt: new Date()
      },
      $setOnInsert: { createdAt: new Date() }
    },
    { upsert: true }
  );
  res.json({ ok: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
  console.log(`Optinex dashboard running on http://localhost:${port}`);
});
