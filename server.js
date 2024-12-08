const path = require("path");
const express = require("express");
const https = require("https");
const fs = require("fs");
const helmet = require("helmet");
const { color } = require("console-log-colors");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth2");
const cookieSession = require("cookie-session");
const { verify } = require("crypto");

require("dotenv").config();

const PORT = 3000;
const config = {
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    COOKIE_KEY_1: process.env.COOKIE_KEY_1,
    COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTION = {
    callbackURL: "/auth/google/callback",
    clientID: config.CLIENT_ID,
    clientSecret: config.CLIENT_SECRET,
};

function verifyCallback(accessToken, refreshToken, profile, done) {
    console.log("Goole progile", profile);
    done(null, profile);
}

passport.use(new Strategy(AUTH_OPTION, verifyCallback));

// Save the session to cookie
passport.serializeUser((user, done) => {
    done(null, user.id);
});

// Read the session from the cookie
passport.deserializeUser((id, done) => {
    done(null, id);
});

const app = express();

app.use(helmet());

app.use(
    cookieSession({
        name: "session",
        maxAge: 24 * 60 * 60 * 1000,
        keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
    })
);

app.use(passport.initialize());
app.use(passport.session());

function checkLoggedIn(req, res, next) {
    console.log(req.user);
    const isLoggedIn = req.user && req.isAuthenticated();
    if (!isLoggedIn) {
        return res.status(401).json({
            error: "you must login",
        });
    }
    next();
}

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.get(
    "/auth/google",
    passport.authenticate("google", {
        scope: ["email"],
    })
);

app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
        failureRedirect: "/failure",
        successRedirect: "/",
        session: true,
    }),
    (req, res) => {
        console.log("Google us callback");
    }
);

app.get("/failure", (req, res) => {
    return res.send("Fail");
});

app.get("/auth/logout", (req, res) => {
    req.logout();
    return res.redirect("/");
});

app.get("/secret", checkLoggedIn, (req, res) => {
    return res.send("you personal secret is 1150");
});

https
    .createServer(
        {
            cert: fs.readFileSync("cert.pem"),
            key: fs.readFileSync("key.pem"),
        },
        app
    )
    .listen(PORT, () => {
        console.log(color.greenBG(`app listening on port ${PORT}...`));
    });
