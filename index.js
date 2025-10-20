const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path'); // Ensure path is required
const { MongoClient, ObjectId } = require('mongodb'); // Import ObjectId
const MongoStore = require('connect-mongo');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// --- Environment Variables ---
const MONGODB_URI = process.env.MONGODB_URI;
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const ALLOWED_DOMAIN = 'lectricebikes.com';

// --- Database Connection ---
const client = new MongoClient(MONGODB_URI);
let spinsCollection;

// ---- NEW: pick an app timezone for “day” calculations ----
const APP_TZ = process.env.APP_TZ || 'America/Phoenix'; // choose your org’s TZ

function dayString(d = new Date()) {
  // en-CA gives YYYY-MM-DD
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: APP_TZ, year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(d);
}

// ---- DB connection: ADD a unique index on (day,email) ----
async function connectToDatabase() {
  try {
    await client.connect();
    const database = client.db('prizeWheelDB');
    spinsCollection = database.collection('spins');
    console.log('Successfully connected to MongoDB Atlas!');

    // Enforce 1 spin per (day,email) at the DB level
    try {
      await spinsCollection.createIndex({ day: 1, email: 1 }, { unique: true });
      console.log('Successfully created or verified unique index on (day, email).');
    } catch (indexErr) {
      if (indexErr.code === 11000) {
        // This is the "duplicate key on build" error.
        console.warn('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
        console.warn('--- WARNING: DUPLICATE DATA DETECTED ---');
        console.warn('MongoDB could not build the unique (day, email) index.');
        console.warn('This means your "spins" collection has duplicate entries.');
        console.warn('The app will RUN, but it is NOT protected from duplicate spins until you fix this.');
        console.warn('To Fix:');
        console.warn('  1. Go to MongoDB Atlas.');
        console.warn('  2. Find and DELETE duplicate records from the "spins" collection.');
        console.warn(`  3. The first duplicate found was: { day: "${indexErr.keyValue?.day}", email: "${indexErr.keyValue?.email}" }`);
        console.warn('  4. After cleaning, restart the server. The index will build successfully.');
        console.warn('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!');
        // DO NOT EXIT. Let the app start.
      } else {
        // Other index error (e.g., options conflict)
        console.error('Failed to create index (non-duplicate error):', indexErr);
        throw indexErr; // Throw to be caught by outer catch
      }
    }
  } catch (err) {
    // This will now catch connection errors OR the re-thrown indexErr
    console.error('Failed to connect to MongoDB', err);
    process.exit(1);
  }
}

// --- Authentication Setup ---
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

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    if (profile._json.hd === ALLOWED_DOMAIN) {
      return done(null, profile);
    } else {
      return done(new Error('Invalid domain.'), null);
    }
  }
));
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/auth/google');
}

// --- Auth Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], hd: ALLOWED_DOMAIN }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login-failed' }), (req, res) => res.redirect('/'));
app.get('/login-failed', (req, res) => res.send('<h1>Login Failed</h1><p>You must use a valid @' + ALLOWED_DOMAIN + ' account.</p>'));

// --- API Routes ---
app.use(express.json());

app.get('/api/user', isLoggedIn, (req, res) => {
  res.json({ name: req.user.displayName, email: req.user.emails[0].value });
});

// ---- NEW: expose the server’s “today” in the app timezone ----
app.get('/api/day', isLoggedIn, (req, res) => {
  const now = new Date();
  return res.json({
    day: dayString(now),
    now: now.toISOString(),
    tz: APP_TZ
  });
});

app.get('/api/spins', isLoggedIn, async (req, res) => {
  console.log('GET /api/spins request received'); // Add logging
  try {
    const allSpins = await spinsCollection.find({}).toArray();
    console.log(`Found ${allSpins.length} spins.`); // Log count
    res.json(allSpins);
  } catch (error) {
    console.error('Failed to fetch spins:', error); // Log the actual error
    res.status(500).json({ error: 'Failed to fetch spins' });
  }
});

// ---- Server now sets ts + day authoritatively and handles duplicates ----
app.post('/api/spins', isLoggedIn, async (req, res) => {
  try {
    const now = new Date();
    const serverDay = dayString(now);

    const doc = {
      // server authoritative fields
      ts: now.toISOString(),
      day: serverDay,
      name: req.user.displayName,
      email: req.user.emails[0].value,

      // client-provided outcome fields
      guess: req.body?.guess,
      landed: req.body?.landed,
      win: !!req.body?.win,
      fp: req.body?.fp || null
    };

    // quick validation
    if (
      !doc.guess ||
      doc.landed == null ||
      typeof doc.win !== 'boolean'
    ) {
      return res.status(400).json({ error: 'Missing required spin data fields.' });
    }

    try {
      const result = await spinsCollection.insertOne(doc);
      const saved = await spinsCollection.findOne({ _id: result.insertedId });
      return res.json(saved);
    } catch (e) {
      // E11000 duplicate key = user already spun today
      if (e && e.code === 11000) {
        const existing = await spinsCollection.findOne({ day: serverDay, email: doc.email });
        return res.status(409).json({ error: 'already-spun', record: existing });
      }
      throw e;
    }
  } catch (error) {
    console.error('Failed to save spin:', error);
    res.status(500).json({ error: 'Failed to save spin' });
  }
});

// ---- Server-side check now uses the same dayString() ----
app.post('/api/check', isLoggedIn, async (req, res) => {
  try {
    const serverDay = dayString(new Date());
    const userEmail = req.user.emails[0].value;
    const hit = await spinsCollection.findOne({ day: serverDay, email: userEmail });
    res.json({ already: !!hit, record: hit || null, day: serverDay });
  } catch (error) {
    console.error('Failed to check limit:', error);
    res.status(500).json({ error: 'Failed to check limit' });
  }
});

// --- Admin Routes (Debug Only) ---
app.get('/api/admin/reset', isLoggedIn, async (req, res) => {
  // We rely on the frontend CONFIG.DEBUG check before calling this
  try {
    const deleteResult = await spinsCollection.deleteMany({});
    res.json({ ok: true, cleared: deleteResult.deletedCount });
  } catch (error) {
     console.error('Failed to clear data:', error);
    res.status(500).json({ error: 'Failed to clear data' });
  }
});

app.get('/api/admin/reset-today', isLoggedIn, async (req, res) => {
  // We rely on the frontend CONFIG.DEBUG check before calling this
  
  // Get the date string from the query parameter sent by the frontend
  const dateToClear = req.query.date; 

  if (!dateToClear || !/^\d{4}-\d{2}-\d{2}$/.test(dateToClear)) {
      // Basic validation for YYYY-MM-DD format
      return res.status(400).json({ error: 'Invalid or missing date parameter. Format: YYYY-MM-DD' });
  }

  console.log(`Attempting to clear records for date: ${dateToClear}`); // Add logging

  try {
    const deleteResult = await spinsCollection.deleteMany({ day: dateToClear });
    console.log(`Cleared ${deleteResult.deletedCount} records for ${dateToClear}`); // Log result
    res.json({ ok: true, cleared: deleteResult.deletedCount });
  } catch (error) {
    console.error(`Failed to clear data for ${dateToClear}:`, error);
    res.status(500).json({ error: `Failed to clear data for ${dateToClear}` });
  }
});

app.post('/api/admin/delete-selected', isLoggedIn, async (req, res) => {
    // We rely on the frontend CONFIG.DEBUG check before calling this
    const { ids } = req.body;

    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'Invalid or empty IDs array' });
    }

    // --- Robust ObjectId Conversion ---
    let objectIds;
    try {
        objectIds = ids.map(id => {
             // Add explicit check for valid hex string format BEFORE conversion
             if (!ObjectId.isValid(id)) { 
                 throw new Error(`Invalid ObjectId format: ${id}`);
             }
             return new ObjectId(id);
        });
    } catch (error) {
        console.error('ObjectId conversion error:', error.message);
        return res.status(400).json({ error: `Invalid ID format provided. ${error.message}` });
    }
    // --- End Robust Conversion ---

    try {
        const deleteResult = await spinsCollection.deleteMany({ _id: { $in: objectIds } });
        res.json({ ok: true, deleted: deleteResult.deletedCount });
    } catch (error) {
        console.error('Failed to delete selected spins:', error);
        res.status(500).json({ error: 'Failed to delete selected spins' });
    }
});


// --- Serve Frontend ---
app.use(isLoggedIn, express.static(path.join(__dirname, 'public')));

// --- Start Server ---
connectToDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});