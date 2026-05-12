require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const app = express();
app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

//MongoDB connection
const client = new MongoClient(process.env.MONGODB_HOST);

let db;

async function connectDB() {
    await client.connect();
    db = client.db(process.env.MONGODB_DATABASE);
    console.log("Connected to MongoDB");
}
connectDB();

//sessions
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_HOST,
        dbName: process.env.MONGODB_DATABASE,
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
}));


//Middleware
function isValidSession(req, res, next) {

    if (req.session.user) {
        next();
    } else {
        res.redirect("/login");
    }
}

function isAdmin(req, res, next) {

    if (req.session.user.user_type === "admin") {
        next();
    } else {

        res.status(403);

        res.send(`
            <h1>403 Forbidden</h1>
             <p>You are not authorized.</p>

             <a href="/" style="
        padding:10px 15px;
        background:black;
        color:white;
        text-decoration:none;
        border-radius:5px;
    ">Go Home</a>
        `);
    }
}

//Home route
app.get("/", (req, res) => {

    res.render("index", {
        user: req.session.user
    });
});

//  Signup Page
app.get("/signup", (req, res) => {
    res.render("signup", {
        user: req.session.user
    });
});

app.post("/signup", async (req, res) => {

    //validate input
    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const result = schema.validate(req.body);

    if (result.error) {
        return res.send(`
            ${result.error.details[0].message}
            <br><br>
            <a href="/signup">Try Again</a>
            `);
    }

    const existingUser = await db.collection("users").findOne({ email: req.body.email });

    if (existingUser) {
        return res.send(`
            Email already exists.
            <br><br>
            <a href="/signup">Try Again</a>
            `);
    }
    //hashpassword
    const hashedPassword = await bcrypt.hash(req.body.password, 12);

    //save to database
    await db.collection("users").insertOne({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
        user_type: "user"
    });

    req.session.user = {
        name: req.body.name,
        email: req.body.email,
        user_type: "user"
    };

    res.redirect("/members");

});

//Login Page
app.get("/login", (req, res) => {

    const error = req.query.error || "";

    res.render("login", {
        error: error,
        user: req.session.user
    });
});

app.post("/login", async (req, res) => {

    const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
    });

    const result = schema.validate(req.body);

    if (result.error) {
        return res.redirect("/login?error=Invalid input");
    }

    const user = await db.collection("users").findOne({
        email: req.body.email
    });

    if (!user) {
        return res.redirect("/login?error=User not found");
    }

    const validPassword = await bcrypt.compare(req.body.password, user.password);

    if (!validPassword) {
        return res.redirect("/login?error=Wrong password");
    }

    req.session.user = {
        name: user.name,
        email: user.email,
        user_type: user.user_type
    };

    res.redirect("/members");
});

//Members Page
app.get("/members", isValidSession, (req, res) => {
    res.render("members", {
        user: req.session.user
    });

});

//Admin Page
app.get("/admin", isValidSession, isAdmin, async (req, res) => {

    const users = await db.collection("users").find().toArray();

    res.render("admin", {
        users: users,
        user: req.session.user
    });
});

//Promote User
app.get("/promote/:email", isValidSession, isAdmin, async (req, res) => {

    await db.collection("users").updateOne(
        { email: req.params.email },
        { $set: { user_type: "admin" } }
    );
    res.redirect("/admin");
});

//Demote User 
app.get("/demote/:email", isValidSession, isAdmin, async (req, res) => {

    await db.collection("users").updateOne(
        { email: req.params.email },
        { $set: { user_type: "user" } }
    );
    res.redirect("/admin");

});


//Logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {

        res.redirect("/");
    });
});

//404 Page
app.use((req, res) => {
    res.status(404);
    res.render("404", {
        user: req.session.user
    });
});

//Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});