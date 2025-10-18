const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const { MongoClient } = require('mongodb');
const MongoStore = require('connect-mongo');
const { ObjectId } = require('mongodb');

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

async function connectToDatabase() {
  try {
    await client.connect();
    const database = client.db('prizeWheelDB');
    spinsCollection = database.collection('spins');
    console.log('Successfully connected to MongoDB Atlas!');
  } catch (err) {
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

app.get('/api/admin/reset-today', isLoggedIn, async (req, res) => {
  if (!process.env.NODE_ENV !== 'development' && !CONFIG.DEBUG) { // Double check for safety
      return res.status(403).json({ error: 'Not allowed in production unless debug enabled' });
  }
  try {
    const today = new Date().toISOString().slice(0, 10); // Use server's date
    const deleteResult = await spinsCollection.deleteMany({ day: today });
    res.json({ ok: true, cleared: deleteResult.deletedCount });
  } catch (error) {
    console.error('Failed to clear today\'s data:', error);
    res.status(500).json({ error: 'Failed to clear today\'s data' });
  }
});

// --- API Routes ---
app.use(express.json());

app.get('/api/user', isLoggedIn, (req, res) => {
  res.json({ name: req.user.displayName, email: req.user.emails[0].value });
});

// THIS WAS THE MISSING ENDPOINT
app.get('/api/spins', isLoggedIn, async (req, res) => {
  try {
    const allSpins = await spinsCollection.find({}).toArray();
    res.json(allSpins);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch spins' });
  }
});

app.post('/api/spins', isLoggedIn, async (req, res) => {
  try {
    const newSpin = req.body;
    newSpin.name = req.user.displayName;
    newSpin.email = req.user.emails[0].value;
    await spinsCollection.insertOne(newSpin);
    res.json(newSpin);
  } catch (error) {
    res.status(500).json({ error: 'Failed to save spin' });
  }
});

app.post('/api/check', isLoggedIn, async (req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const userEmail = req.user.emails[0].value;
    const hit = await spinsCollection.findOne({ day: today, email: userEmail });
    res.json({ already: !!hit, record: hit || null });
  } catch (error) {
    res.status(500).json({ error: 'Failed to check limit' });
  }
});

app.post('/api/admin/delete-selected', isLoggedIn, async (req, res) => {
    if (!process.env.NODE_ENV !== 'development' && !CONFIG.DEBUG) { // Safety check
        return res.status(403).json({ error: 'Not allowed' });
    }
    const { ids } = req.body; // Expect an array of string IDs

    if (!Array.isArray(ids) || ids.length === 0) {
        return res.status(400).json({ error: 'Invalid or empty IDs array' });
    }

    try {
        // Convert string IDs to MongoDB ObjectId type
        const objectIds = ids.map(id => new ObjectId(id)); 
        const deleteResult = await spinsCollection.deleteMany({ _id: { $in: objectIds } });
        res.json({ ok: true, deleted: deleteResult.deletedCount });
    } catch (error) {
        console.error('Failed to delete selected spins:', error);
        // Check specifically for ObjectId conversion errors
        if (error.message.includes('Argument passed in must be a string of 12 bytes or a string of 24 hex characters')) {
             return res.status(400).json({ error: 'One or more invalid IDs provided.' });
        }
        res.status(500).json({ error: 'Failed to delete selected spins' });
    }
});

app.get('/api/admin/reset', isLoggedIn, async (req, res) => {
  try {
    const deleteResult = await spinsCollection.deleteMany({});
    res.json({ ok: true, cleared: deleteResult.deletedCount });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clear data' });
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