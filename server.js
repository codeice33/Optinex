const cors = require('cors');
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

const inMemoryDashboardStates = [];
const inMemoryUsers = [];

function createInMemoryCollection(store) {
  return {
    async createIndex() {},
    async findOne(query = {}) {
      if (query.$or) {
        return store.find(item => query.$or.some(condition => {
          if (condition.username !== undefined) {
            return item.username === String(condition.username).trim().toLowerCase();
          }
          if (condition.email !== undefined) {
            return item.email === String(condition.email).trim().toLowerCase();
          }
          return false;
        })) || null;
      }

      if (query.username !== undefined && query.country !== undefined) {
        const username = String(query.username).trim().toLowerCase();
        const country = String(query.country).trim().toLowerCase();
        return store.find(item => item.username === username && item.country === country) || null;
      }

      if (query.username !== undefined) {
        const username = String(query.username).trim().toLowerCase();
        return store.find(item => item.username === username) || null;
      }

      if (query.email !== undefined) {
        const email = String(query.email).trim().toLowerCase();
        return store.find(item => item.email === email) || null;
      }

      return null;
    },
    async insertOne(doc) {
      store.push(doc);
      return { acknowledged: true, insertedId: doc._id || store.length };
    },
    async updateOne(filter = {}, update = {}) {
      const existingIndex = store.findIndex(item => {
        if (filter.username !== undefined && filter.country !== undefined) {
          return item.username === String(filter.username).trim().toLowerCase() && item.country === String(filter.country).trim().toLowerCase();
        }
        if (filter.username !== undefined) {
          return item.username === String(filter.username).trim().toLowerCase();
        }
        if (filter.email !== undefined) {
          return item.email === String(filter.email).trim().toLowerCase();
        }
        return false;
      });

      const nextDoc = existingIndex >= 0 ? { ...store[existingIndex] } : {};
      const mergedDoc = { ...nextDoc, ...(update.$set || {}), ...(update.$setOnInsert || {}) };

      if (existingIndex >= 0) {
        store[existingIndex] = mergedDoc;
        return { acknowledged: true, modifiedCount: 1, upsertedCount: 0 };
      }

      store.push(mergedDoc);
      return { acknowledged: true, modifiedCount: 0, upsertedCount: 1 };
    }
  };
}

// Enable CORS
app.use(cors({
  origin: function(origin, callback) {
    const allowedOrigins = [
      'https://optinex.xtys.dev',
      'https://www.optinex.xtys.dev',
      'https://optinex.onrender.com',
      'http://localhost:3000',
      'http://localhost:5500',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5500'
    ];

    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
      return;
    }

    callback(null, false);
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: true
}));
app.options('*', cors());

app.use(express.json({ limit: '1mb' }));
app.use(express.static(__dirname));

function normalizeKey(username, country) {
  return {
    username: String(username || '').trim().toLowerCase(),
    country: String(country || 'Nigeria').trim().toLowerCase()
  };
}

async function getCollection() {
  if (!mongoUri) {
    if (!dashboardStates) {
      dashboardStates = createInMemoryCollection(inMemoryDashboardStates);
      users = createInMemoryCollection(inMemoryUsers);
    }
    return dashboardStates;
  }

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

function verifyPassword(password, salt, hash) {
  if (!password || !salt || !hash) return false;
  const candidate = crypto.pbkdf2Sync(String(password), salt, 120000, 64, 'sha512').toString('hex');
  return candidate === hash;
}

app.post('/api/login', async (req, res) => {
  const collection = await getUsersCollection().catch(() => null);
  if (!collection) {
    res.status(503).json({ error: 'database not configured' });
    return;
  }

  const identifier = String(req.body.identifier || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!identifier || !password) {
    res.status(400).json({ error: 'username/email and password are required' });
    return;
  }

  const user = await collection.findOne({ $or: [{ username: identifier }, { email: identifier }] });
  if (!user) {
    res.status(404).json({ error: 'No account found with that username or email.' });
    return;
  }

  if (!verifyPassword(password, user.passwordSalt, user.passwordHash)) {
    res.status(401).json({ error: 'Incorrect password. Please try again.' });
    return;
  }

  res.json({ ok: true, user: { username: user.username, email: user.email, country: user.country || 'Nigeria' } });
});

app.get('/api/health', async (req, res) => {
  try {
    const collection = await getCollection();

    res.json({
      ok: true,
      database: collection ? "connected" : "not_configured",
      hasMongoUri: !!process.env.MONGODB_URI,
      dbName: process.env.MONGODB_DB || "optinex"
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: err.message,
      hasMongoUri: !!process.env.MONGODB_URI
    });
  }
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
    streakDays: Math.max(0, Number.parseInt(req.body.streakDays, 10) || 0),
    streakLastLogin: Math.max(0, Number.parseInt(req.body.streakLastLogin, 10) || 0),
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
