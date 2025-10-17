const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// --- 1. Authentication Setup ---
// IMPORTANT: Replace with your actual credentials from Google Cloud
const GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID';
const GOOGLE_CLIENT_SECRET = 'YOUR_GOOGLE_CLIENT_SECRET';
const SESSION_SECRET = 'a-very-secret-key-change-this'; // Change this to a random string

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


// --- 5. Serve the Frontend ---
// All routes under this line require a user to be logged in first
app.use(isLoggedIn, express.static(path.join(__dirname, 'public')));


// --- 6. Start the Server ---
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});