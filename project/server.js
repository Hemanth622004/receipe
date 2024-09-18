var express = require('express');
var app = express();
const admin = require("firebase-admin");
const { getFirestore } = require('firebase-admin/firestore');
const crypto = require('crypto');
var serviceAccount = require("./key.json");
const bcrypt = require("bcrypt");
const session = require("express-session"); // To handle sessions
const path = require('path');
// Generate a random key for session management
const secretKey = crypto.randomBytes(32).toString('hex');

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = getFirestore();

// Middleware to serve static files and parse request bodies

app.use(express.urlencoded({ extended: true }));

// Session setup (to track logged-in status)
app.use(session({
  secret: secretKey, // Use the generated secret key
  resave: false,
  saveUninitialized: true,
}));

// Redirect root to signup page if not logged in
app.get('/', function (req, res) {

  res.sendFile(__dirname + '/public/signup.html');
});

// Serve the signup page
app.get('/signup', function (req, res) {
  res.sendFile(__dirname + '/public/signup.html');
});

// Serve the login page
app.get('/login', function (req, res) {
  res.sendFile(__dirname + '/public/login.html');
});

app.get('/index', function (req, res) {
  res.sendFile(__dirname + '/public/index.html');
});

// Logout route
// Logout route
app.get('/logout', function (req, res) {
  req.session.destroy(function (err) {
    if (err) {
      console.error("Error destroying session: ", err);
      return res.status(500).send("An error occurred while logging out.");
    }
    // At this point, the session is destroyed. No need to log `req.session` or `res.session`.
    res.redirect('/login'); // Redirect to login page after logging out
  });
});


app.use(express.static(path.join(__dirname, 'public')));
// Handle signup form submission
app.post('/signupSubmit', async (req, res) => {
  const { Fullname, Email, Password } = req.body;
  if (!Fullname || !Email || !Password) {
    return res.status(400).send("Please provide all required fields.");
  }

  try {
    const emailExists = await checkEmailExists(Email);
    if (emailExists) {
      return res.send("<script>alert('Email already exists.'); window.history.back();</script>");
    }

    const hashedPassword = await hashPassword(Password);
    await db.collection('Users').add({ Fullname, Email, Password: hashedPassword });
    res.redirect('/login');
  } catch (error) {
    console.error("Error hashing or adding document to Firestore: ", error);
    res.status(500).send("An error occurred while signing up.");
  }
});

// Handle login form submission
app.post('/loginSubmit', async (req, res) => {
  const { Email, Password } = req.body;
  if (!Email || !Password) {
    return res.status(400).send("Please provide both Email and Password.");
  }

  try {
    const querySnapshot = await db.collection('Users').where("Email", "==", Email).get();
    if (querySnapshot.empty) {
      return res.send("Login Failed");
    }

    const user = querySnapshot.docs[0].data();
    const hashedPassword = user.Password;
    const passwordMatch = await bcrypt.compare(Password, hashedPassword);

    if (passwordMatch) {
      req.session.loggedIn = true; // Set session to track login status
      res.redirect('/index'); // Redirect to the recipe search page
    } else {
      res.send("Login Failed");
    }
  } catch (error) {
    console.error("Error querying Firestore or comparing passwords: ", error);
    res.status(500).send("An error occurred while attempting to log in.");
  }
});

// Function to hash a password
async function hashPassword(plainPassword) {
  return await bcrypt.hash(plainPassword, 10); // 10 is the number of salt rounds
}

// Function to check if an email already exists in the database
async function checkEmailExists(email) {
  const querySnapshot = await db.collection('Users').where("Email", "==", email).get();
  return !querySnapshot.empty;
}

// Start server
app.listen(3000, function () {
  console.log('App listening on port 3000!');
});
