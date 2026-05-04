require("dotenv").config();

const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const Joi = require("joi");

const app = express();

app.use(express.urlencoded({ extended: true }));

//MongoDB connection
const client = new MongoClient(process.env.MONGODB_HOST);

let db;

async function connectDB() {
    await client.connect();
    db = client.db("users");
    console.log("Connected to MongoDB");
}
connectDB();

//sessions
app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_HOST,
        crypto: {
            secret: process.env.MONGODB_SESSION_SECRET
        }
    }),
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

//Home route
app.get("/", (req, res) => {

    if (!req.session.name) {
        res.send(`
    <h2>Home</h2>
    <a href="/signup">Signup</a><br>
    <a href="/login">Login</a>
    `)
    } else {
        res.send(`
                <h2>Welcome ${req.session.name}</h2>
                <a href="/members">Members</a><br>
                <a href="/logout>Logout</a>
                `);
    }
});

//  Signup Page
app.get("/signup", (req, res) => {
    res.send(`
        <h2>Signup</h2>
        <form method="Post" action="/signup">
        Name: <input name="name"></br>
        Email: <input name="email"></br>
        Password: <input type="password" name="password"></br>
        <button type="submit">Signup</button>
        </form>
        `);

});

app.post("/signup", async (req, res) => {

    //validate input
    const schema = Joi.object({
        name: Joi.string().required(),
        email: Joi.string().required(),
        password: Joi.string().required()
    });

    const result = schema.validate(req.body);

    if (result.error) {
        return res.send("Invalid input");
    }

    //hashpassword
    const hashedPassword = await bcrypt.hash(req.body.password, 10);

    //save to database
    await db.collection("users").insertOne({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    });

    req.session.name = req.body.name;

    res.redirect("/members");

});

//Login Page
app.get("/login", (req, res) => {
    res.send(`
            <h2>Login</h2>
            <form method="POST" action="/login">
            Email: <input name="email"></br>
            Password: <input type="password" name="password"></br>
            <button type="submit">Login</button>
            </form>
            `);
});

app.post("/login", async (req, res) => {

    const user = await db.collection("users").findOne({
        email: req.body.email
    });

    if (!user) {
        return res.send("User not found");
    }

    const valid = await bcrypt.compare(req.body.password, user.password);

    if (!valid) {
        return res.send("Wrong password");
    }

    req.session.name = user.name;

    res.redirect("/members");
});

//Members Page
app.get("/members", (req, res) => {

    if (!req.session.name) {
        return res.redirect("/login");

    }

    res.send(`<h2>Welcome ${req.session.name}</h2>
        <a href="/logout">Logout</a>`);
});

app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

//404 Page
app.use((req, res) => {
    res.status(404).send("Page not found");
});

//Start server

app.listen(3000, () => {
    console.log("Server running on port 3000");
});