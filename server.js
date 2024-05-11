const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const swaggerJSDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const dotenv = require("dotenv");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth").OAuth2Strategy;

const app = express();
dotenv.config();
const PORT = process.env.PORT;

app.use(bodyParser.json());
app.set("view engine", "ejs");
app.use(
  session({
    resave: false,
    saveUninitialized: true,
    secret: "SECRET",
  })
);

const swaggerOptions = {
    swaggerDefinition: {
      openapi: "3.0.0",
      info: {
        title: "Express Swagger API",
        version: "1.0.0",
        description: "APIs documentation for the Express.js app",
      },
      servers: [{ url: "http://localhost:3000" }],
      components: {
        securitySchemes: {
          bearerAuth: {
            type: "http",
            scheme: "bearer",
            bearerFormat: "JWT",
            in: "header",
          },
        },
        schemas: {
          User: {
            type: "object",
            properties: {
              photo: { type: "string" },
              name: { type: "string" },
              bio: { type: "string" },
              phone: { type: "string" },
              email: { type: "string" },
              password: { type: "string" },
              isPrivate: { type: "boolean" },
              isAdmin: { type: "boolean" },
            },
          },
        },
      },
      security: [{ bearerAuth: [] }],
    },
    apis: ["./server.js"],
  };



const swaggerSpec = swaggerJSDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

mongoose.connect(process.env.MONGO_URL);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", function () {
  console.log("Connected to MongoDB");
});

let userProfile;

app.use(passport.initialize());
app.use(passport.session());

app.set("view engine", "ejs");

app.get("/success", (req, res) => res.send(userProfile));
app.get("/error", (req, res) => res.send("error logging in"));

passport.serializeUser(function (user, cb) {
  cb(null, user);
});

passport.deserializeUser(function (obj, cb) {
  cb(null, obj);
});

const GOOGLE_CLIENT_ID =
  process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
passport.use(
  new GoogleStrategy(
    {
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
    function (accessToken, refreshToken, profile, done) {
      userProfile = profile;
      return done(null, userProfile);
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/error" }),
  function (req, res) {
    res.redirect("/success");
  }
);

const userSchema = new mongoose.Schema({
  photo: String,
  name: String,
  bio: String,
  phone: String,
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isPrivate: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false },
});

const User = mongoose.model("User", userSchema);

async function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token)
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token.split(' ')[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: "Invalid token." });
  }
}

app.get("/", function (req, res) {
  res.render("pages/auth");
});


app.post("/register", async (req, res) => {
  try {
    const { photo, name, bio, phone, email, password, isPrivate, isAdmin } =
      req.body;
    if (!bio || !name || !email || !password || !phone)
      return res.status(400).json({ message: "All fields are required." });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email is already registered." });
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({
      photo,
      name,
      bio,
      phone,
      email,
      password: hashedPassword,
      isPrivate,
      isAdmin,
    });
    await user.save();
    res.status(201).json({ message: "User registered successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});



app.post("/admin/register", async (req, res) => {
    try {
      const { photo, name, bio, phone, email, password, isPrivate, isAdmin } =
        req.body;
      if (!bio || !name || !email || !password || !phone)
        return res.status(400).json({ message: "All fields are required." });
  
      const existingUser = await User.findOne({ email, isAdmin: true });
      if (existingUser)
        return res.status(400).json({ message: "Email is already registered." });
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({
        photo,
        name,
        bio,
        phone,
        email,
        password: hashedPassword,
        isPrivate,
        isAdmin: true,
      });
      await user.save();
      res.status(201).json({ message: "User registered successfully." });
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  });




app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid email or password." });
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword)
      return res.status(400).json({ message: "Invalid email or password." });

    const token = jwt.sign(
      { email: user.email, isAdmin: user.isAdmin, isPrivate: user.isPrivate },
      process.env.JWT_SECRET
    );
    res.json({ token });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


app.get("/profile", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const user = await db
      .collection("users")
      .findOne({ email: userEmail }, { projection: { _id: 0 } });
    if (!user) return res.status(404).json({ message: "User not found." });
    res.json(user);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


app.put("/profile/photo", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const { photo } = req.body;

    if (!photo) {
      return res
        .status(400)
        .json({ message: "Please provide photo or image URL." });
    }

    const updateData = {};
    if (photo) updateData.photo = photo;

    await db
      .collection("users")
      .updateOne({ email: userEmail }, { $set: updateData });

    res.json({ message: "User photo updated successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


app.put("/profile/privacy", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const userEmail = loggedInUser.email;
    const { isPrivate } = req.body;

    await db
      .collection("users")
      .updateOne({ email: userEmail }, { $set: { isPrivate } });

    res.json({ message: "User privacy setting updated successfully." });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


app.get("/users", verifyToken, async (req, res) => {
  try {
    const loggedInUser = req.user;
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;
    if (loggedInUser.isAdmin) {
      const users = await db
        .collection("users")
        .find({}, { projection: { _id: 0, password: 0 } })
        .skip(parseInt(skip))
        .limit(parseInt(limit))
        .toArray();
      res.json(users);
    } else {
      const users = await db
        .collection("users")
        .find({ isPrivate: false }, { projection: { _id: 0, password: 0 } })
        .skip(parseInt(skip))
        .limit(parseInt(limit))
        .toArray();
      res.json(users);
    }
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
