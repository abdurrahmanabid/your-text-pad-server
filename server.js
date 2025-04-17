require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// Middleware
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
  })
);

app.use(express.json());

// Database Connection
mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/auth_demo", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User Model
const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    theme: { type: Boolean, default: false }, // true for dark mode, false for light mode
  },
  { timestamps: true }
);

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

UserSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", UserSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Auth Middleware
// In your server.js (backend)
const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        error: "Please authenticate",
        details: "No token provided",
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ _id: decoded._id });

    if (!user) {
      return res.status(401).json({
        error: "Please authenticate",
        details: "User not found",
      });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    let details = "Invalid token";
    if (err.name === "TokenExpiredError") {
      details = "Token expired";
    } else if (err.name === "JsonWebTokenError") {
      details = "Invalid token format";
    }

    res.status(401).json({
      error: "Please authenticate",
      details,
    });
  }
};

const FileSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    content: { type: String, required: true },
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  { timestamps: true }
);

const File = mongoose.model("File", FileSchema);

// File routes
app.post("/api/files", authMiddleware, async (req, res) => {
  try {
    const { title, content } = req.body;

    const file = new File({
      title,
      content,
      owner: req.user._id,
    });

    await file.save();
    res.status(201).json(file);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/files", authMiddleware, async (req, res) => {
  try {
    const files = await File.find({ owner: req.user._id });
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Routes
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const user = new User({ name, email, password });
    await user.save();

    const token = jwt.sign({ _id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.status(201).json({ user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ _id: user._id }, JWT_SECRET, { expiresIn: "7d" });

    res.json({ user, token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  res.json(req.user);
});
// Add this to your existing server.js
app.post("/api/logout", authMiddleware, async (req, res) => {
  try {
    // In a real app, you might want to invalidate the token
    res.status(200).send({ message: "Logged out successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
// Add these to your existing server routes

// Get all files for user
app.get('/api/files', authMiddleware, async (req, res) => {
  try {
    const files = await File.find({ owner: req.user._id }).sort({ updatedAt: -1 });
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a file
app.delete('/api/files/:id', authMiddleware, async (req, res) => {
  try {
    const file = await File.findOneAndDelete({ 
      _id: req.params.id, 
      owner: req.user._id 
    });
    
    if (!file) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    res.json({ message: 'File deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
