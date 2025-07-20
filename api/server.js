const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const session = require("express-session");
const KnexSessionStore = require("connect-session-knex")(session);

const authRouter = require("./auth/auth-router.js");
const usersRouter = require("./users/users-router.js");

const server = express();

/**
  Do what needs to be done to support sessions with the `express-session` package!
  To respect users' privacy, do NOT send them a cookie unless they log in.
  This is achieved by setting 'saveUninitialized' to false, and by not
  changing the `req.session` object unless the user authenticates.

  Users that do authenticate should have a session persisted on the server,
  and a cookie set on the client. The name of the cookie should be "chocolatechip".

  The session can be persisted in memory (would not be adecuate for production)
  or you can use a session store like `connect-session-knex`.
 */

server.use(session({

    name: "chocolatechip", // Name of the cookie
    secret: 'boobs are yours', //process.env.SESSION_SECRET
    saveUninitialized: false, // Do not save uninitialized sessions
    resave: false, // Do not resave sessions that have not been modified
    store: new KnexSessionStore({
        knex: require("../data/db-config.js"), // Import your Knex configuration
        tablename: "sessions", // Name of the table where sessions will be stored
        sidfieldname: "sid", // Name of the field that stores the session ID
        createtable: true, // Create the table if it does not exist
        clearInterval: 1000 * 60 * 60, // Clear expired sessions every hour
    }),
    cookie: {
        maxAge: 1000 * 60 * 60, // Cookie expiration time (1 hour)
        secure: false, // Set to true if using HTTPS
        httpOnly: true, // Prevents client-side JavaScript from accessing the cookie
        //sameSite: 'strict', // Helps prevent CSRF attacks
    }

})
);

server.use(helmet());
server.use(express.json());
server.use(cors());


server.use('/api/auth', authRouter)
server.use('/api/users', usersRouter)

server.get("*", (req, res) => {
  res.status(404).json({ message: 'not found!' });
});

server.use((err, req, res, next) => { // eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
