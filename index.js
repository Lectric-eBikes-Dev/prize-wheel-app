// index.js
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');
const MongoStore = require('connect-mongo');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// ----- ENV -----
const MONGODB_URI       = process.env.MONGODB_URI;
const GOOGLE_CLIENT_ID  = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_SECRET     = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET    = process.env.SESSION_SECRET;
const ALLOWED_DOMAIN    = process.env.ALLOWED_DOMAIN || 'lectricebikes.com';
// Timezone used to compute the *app* day (so client & server agree)
const APP_TZ            = process.env.APP_TZ || 'America/Phoenix';

// ----- DB -----
const client = new MongoClient(MONGODB_URI);
let spinsCollection;

function dayString(d = new Date()) {
  // en-CA yields YYYY-MM-DD; timeZone ensures calendar day is stable for your org
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: APP_TZ, year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(d);
}

async function connectToDatabase() {
  try {
    await client.connect();
    const db = client.db('prizeWheelDB');
    spinsCollection = db.collection('spins');
    console.log('[DB] Connected');

    // Enforce one spin per email per day at the DB layer
    await spinsCollection.createIndex({ day: 1, email: 1 }, { unique: true });
  } catch (err) {
    console.error('[DB] Failed to connect', err);
    process.exit(1);
  }
}

// ----- Auth -----
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    dbName: 'prizeWheelDB',
    collectionName: 'sessions',
    ttl: 14 * 24 * 60 * 60
  })
}));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy(
  { clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_SECRET, callbackURL: '/auth/google/callback' },
  (accessToken, refreshToken, profile, done) => {
    // Restrict to your Google Workspace domain
    if (profile._json && profile._json.hd === ALLOWED_DOMAIN) return done(null, profile);
    return done(new Error('Invalid domain'), null);
  }
));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/google');
}

// ----- Auth Routes -----
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'], hd: ALLOWED_DOMAIN })
);
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-failed' }),
  (req, res) => res.redirect('/')
);
app.get('/login-failed', (req, res) => {
  res.status(401).send(`<h1>Login Failed</h1><p>You must use an @${ALLOWED_DOMAIN} account.</p>`);
});

// ----- API -----
app.use(express.json());

// Who am I
app.get('/api/user', isLoggedIn, (req, res) => {
  res.json({ name: req.user.displayName, email: req.user.emails[0].value });
});

// Server authoritative day (client uses this to align UI)
app.get('/api/day', isLoggedIn, (req, res) => {
  const now = new Date();
  res.json({ day: dayString(now), now: now.toISOString(), tz: APP_TZ });
});

// Get all spins (for feed/board)
app.get('/api/spins', isLoggedIn, async (req, res) => {
  try {
    const all = await spinsCollection.find({}).toArray();
    res.json(all);
  } catch (err) {
    console.error('[GET /api/spins] Error:', err);
    res.status(500).json({ error: 'Failed to fetch spins' });
  }
});

// Save a spin (server sets day+ts and enforces one per day)
app.post('/api/spins', isLoggedIn, async (req, res) => {
  try {
    const now = new Date();
    const serverDay = dayString(now);
    const doc = {
      ts: now.toISOString(),
      day: serverDay,
      name: req.user.displayName,
      email: req.user.emails[0].value,
      guess: req.body?.guess,
      landed: req.body?.landed,
      win: !!req.body?.win,
      fp: req.body?.fp || null,
    };

    // minimal validation
    if (!doc.guess || doc.landed == null || typeof doc.win !== 'boolean') {
      return res.status(400).json({ error: 'Missing required spin data fields.' });
    }

    try {
      const result = await spinsCollection.insertOne(doc);
      const saved = await spinsCollection.findOne({ _id: result.insertedId });
      return res.json(saved);
    } catch (e) {
      if (e && e.code === 11000) {
        // Duplicate key => already spun today
        const existing = await spinsCollection.findOne({ day: serverDay, email: doc.email });
        return res.status(409).json({ error: 'already-spun', record: existing });
      }
      throw e;
    }
  } catch (err) {
    console.error('[POST /api/spins] Error:', err);
    res.status(500).json({ error: 'Failed to save spin' });
  }
});

// Check limit (has user spun today?)
app.post('/api/check', isLoggedIn, async (req, res) => {
  try {
    const serverDay = dayString(new Date());
    const userEmail = req.user.emails[0].value;
    const hit = await spinsCollection.findOne({ day: serverDay, email: userEmail });
    res.json({ already: !!hit, record: hit || null, day: serverDay });
  } catch (err) {
    console.error('[POST /api/check] Error:', err);
    res.status(500).json({ error: 'Failed to check limit' });
  }
});

// ----- Admin (use from DEBUG mode only) -----
app.get('/api/admin/reset', isLoggedIn, async (req, res) => {
  try {
    const r = await spinsCollection.deleteMany({});
    res.json({ ok: true, cleared: r.deletedCount });
  } catch (err) {
    console.error('[GET /api/admin/reset] Error:', err);
    res.status(500).json({ error: 'Failed to clear data' });
  }
});

// Clear selected day (?date=YYYY-MM-DD)
app.get('/api/admin/reset-today', isLoggedIn, async (req, res) => {
  const dateToClear = req.query.date;
  if (!dateToClear || !/^\d{4}-\d{2}-\d{2}$/.test(dateToClear)) {
    return res.status(400).json({ error: 'Invalid or missing date parameter (YYYY-MM-DD).' });
  }
  try {
    const r = await spinsCollection.deleteMany({ day: dateToClear });
    res.json({ ok: true, cleared: r.deletedCount });
  } catch (err) {
    console.error('[GET /api/admin/reset-today] Error:', err);
    res.status(500).json({ error: `Failed to clear data for ${dateToClear}` });
  }
});

// Delete selected by _id
app.post('/api/admin/delete-selected', isLoggedIn, async (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ error: 'Invalid or empty IDs array' });
  }
  let objectIds;
  try {
    objectIds = ids.map(id => {
      if (!ObjectId.isValid(id)) throw new Error(`Invalid ObjectId: ${id}`);
      return new ObjectId(id);
    });
  } catch (err) {
    return res.status(400).json({ error: `Invalid ID format. ${err.message}` });
  }
  try {
    const r = await spinsCollection.deleteMany({ _id: { $in: objectIds } });
    res.json({ ok: true, deleted: r.deletedCount });
  } catch (err) {
    console.error('[POST /api/admin/delete-selected] Error:', err);
    res.status(500).json({ error: 'Failed to delete selected spins' });
  }
});

// ----- Frontend -----
app.use(isLoggedIn, express.static(path.join(__dirname, 'public')));

// ----- Start -----
connectToDatabase().then(() => {
  app.listen(PORT, () => console.log(`Server listening on :${PORT}`));
});
