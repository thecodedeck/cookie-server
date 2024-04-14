require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const cors = require("cors");
const isAuthenticated = require("./middleware/is-authenticated");
const User = require("./models/User");
const app = express();

const session = require("express-session");
const MongoStore = require("connect-mongo");

// Connecting to MongoDB
mongoose.connect(process.env.MONGODB_URI);

// Debugging the connection
const db = mongoose.connection;

db.on("error", console.error.bind(console, "connection error:"));
db.once("open", function () {
  console.log("Successfully connected to MongoDB!");
});

app.use(express.json());

const corsOptions = {
  origin: "http://localhost:4200", // Allow the frontend to connect to the server
  credentials: true, // Allow credentials, required for sessions with authentication
};

// Enable CORS
app.use(cors(corsOptions));

// Middleware to create a session ID
// When using req.session, the session ID will be stored in the cookie and the session data will be stored in memory (by default)
app.use(
  session({
    secret: process.env.SUPER_SECRET_KEY, // Secret key for session
    resave: false, // Avoids resaving sessions that haven't changed
    saveUninitialized: true, // Saves new sessions
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      maxAge: 1000 * 60 * 60 * 24, // Time in milliseconds (1 day)
    }), // Store the session in MongoDB, overrides the default memory store

    // This configuration ensures that the cookie is sent over HTTPS (if available) and is not accessible through client-side scripts
    cookie: { secure: "auto", httpOnly: true, maxAge: 1000 * 60 * 60 * 24 }, // Max age in milliseconds (1 day)
  })
);

// Registration
app.post("/sign-up", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the username is already taken
    const existing = await User.findOne({ username });

    if (existing) {
      return res.status(400).send({ message: "Username already taken." });
    }
    // Create a new user
    const user = new User({ username, password });
    await user.save();

    res.status(201).send({ message: "User registered successfully." });
  } catch (error) {
    res.status(400).send(error);
  }
});

// Login
app.post("/sign-in", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).send({ message: "Authentication failed" });
    }

    // Set user information in session
    req.session.user = { id: user._id, username: user.username };
    res.status(200).send({ message: "Logged in successfully" }); // Set-Cookie header will be sent with the response
  } catch (error) {
    console.log(error);
    res.status(500).send(error);
  }
});

// Logout
app.post("/logout", (req, res) => {
  if (req.session) {
    // Destroying the session
    req.session.destroy((err) => {
      if (err) {
        return res
          .status(500)
          .send({ message: "Could not log out, please try again" });
      } else {
        res.send({ message: "Logout successful" });
      }
    });
  } else {
    res.status(400).send({ message: "You are not logged in" });
  }
});

// Delete user, admin only
app.delete("/user/:id", isAuthenticated, async (req, res) => {
  try {
    const id = req.session.user.id;

    const admin = await User.findById(id);

    if (!admin || admin.role !== "admin") {
      return res.status(401).send({ message: "Unauthorized" });
    }

    const user = await User.findById(req.params.id);
    if (!user) {
      return res.status(404).send({ message: "User not found" });
    }

    await user.remove();

    res.send({ message: "User deleted successfully" });
  } catch (error) {
    res.status(500).send(error);
  }
});

// Using auth middleware to check if the user is authenticated
// The middleware will check if the user is logged in by checking the session
// If the user is logged in, the request will be passed to the endpoint
// If the user is not logged in, the middleware will return a 401 status
app.get("/is-authenticated", isAuthenticated, (req, res) => {
  res.status(200).send({ message: "Authenticated" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
