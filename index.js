const express = require('express');
app.set('trust proxy', 1);
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
//const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
//const DATA_FILE = path.join(__dirname, 'data.json');

const { MongoClient } = require('mongodb');

// Get the connection string from your Render environment variables
const MONGODB_URI = process.env.MONGODB_URI; 
const client = new MongoClient(MONGODB_URI);
let spinsCollection;

// Function to connect to the database when the server starts
async function connectToDatabase() {
  try {
    await client.connect();
    const database = client.db('prizeWheelDB'); // You can name your database anything
    spinsCollection = database.collection('spins');
    console.log('Successfully connected to MongoDB Atlas!');
  } catch (err) {
    console.error('Failed to connect to MongoDB', err);
    process.exit(1); // Exit if we can't connect
  }
}

// --- 1. Authentication Setup ---
// IMPORTANT: Replace with your actual credentials from Google Cloud
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;

// ADD THESE THREE LINES FOR DEBUGGING
console.log('--- Checking Environment Variables ---');
console.log('GOOGLE_CLIENT_ID:', GOOGLE_CLIENT_ID ? 'Loaded' : 'NOT FOUND');
console.log('SESSION_SECRET:', SESSION_SECRET ? 'Loaded' : 'NOT FOUND');
console.log('------------------------------------');

// Allowed email domain
const ALLOWED_DOMAIN = 'lectricebikes.com';

app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
  },
  (accessToken, refreshToken, profile, done) => {
    // Check if the user's email domain is allowed
    if (profile._json.hd === ALLOWED_DOMAIN) {
      return done(null, profile);
    } else {
      return done(new Error('Invalid domain.'), null);
    }
  }
));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// --- 2. Middleware to Protect Routes ---
// This function acts as a bouncer, checking if a user is logged in
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/auth/google'); // If not logged in, send them to the Google login page
}

// --- 3. Authentication Routes ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'], hd: ALLOWED_DOMAIN }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-failed' }),
  (req, res) => {
    res.redirect('/'); // Successful login, redirect to the main prize wheel page
  }
);

app.get('/login-failed', (req, res) => {
  res.send('<h1>Login Failed</h1><p>You must use a valid @' + ALLOWED_DOMAIN + ' account.</p>');
});

app.get('/logout', (req, res) => {
    req.logout(() => {
        res.redirect('/');
    });
});


// --- 4. API Routes (Your old Apps Script logic, now in Express) ---
app.use(express.json()); // Middleware to parse JSON bodies

// Function to read data from the JSON file
const readData = () => {
  if (!fs.existsSync(DATA_FILE)) {
    return { spins: [] };
  }
  return JSON.parse(fs.readFileSync(DATA_FILE));
};

// Function to write data to the JSON file
const writeData = (data) => {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
};

/*
app.post('/api/spins', isLoggedIn, (req, res) => {
  const data = readData();
  const newSpin = req.body;
  newSpin.user = req.user.displayName; // Add user info from session
  newSpin.email = req.user.emails[0].value;
  data.spins.push(newSpin);
  writeData(data);
  res.json(newSpin);
});

app.post('/api/check', isLoggedIn, (req, res) => {
    const data = readData();
    const today = new Date().toISOString().slice(0, 10);
    const userEmail = req.user.emails[0].value;

    const hit = data.spins.find(s => s.day === today && s.email === userEmail);
    res.json({ already: !!hit, record: hit || null });
});
*/

app.post('/api/spins', isLoggedIn, async (req, res) => {
  try {
    const newSpin = req.body;
    newSpin.user = req.user.displayName;
    newSpin.email = req.user.emails[0].value;
    
    await spinsCollection.insertOne(newSpin);
    res.json(newSpin);
  } catch (error) {
    console.error('Failed to save spin:', error);
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
    console.error('Failed to check limit:', error);
    res.status(500).json({ error: 'Failed to check limit' });
  }
});


// --- 5. Serve the Frontend ---
// All routes under this line require a user to be logged in first
app.use(isLoggedIn, express.static(path.join(__dirname, 'public')));


// --- 6. Start the Server ---
// Connect to DB and then start the server
connectToDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
  });
});