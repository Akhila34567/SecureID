const Database = require("better-sqlite3");
const path = require("path");


// =====================================================
// DATABASE
// =====================================================

const dbPath =
    path.join(
        __dirname,
        "secureid.db"
    );


const db =
    new Database(dbPath);


// =====================================================
// USERS TABLE
// =====================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS users (

        user_id TEXT PRIMARY KEY,

        name TEXT NOT NULL,

        email TEXT NOT NULL UNIQUE,

        phone TEXT NOT NULL,

        password_hash TEXT NOT NULL,

        email_verified INTEGER DEFAULT 0,

        sms_verified INTEGER DEFAULT 0,

        mfa_enabled INTEGER DEFAULT 0,

        failed_login_attempts INTEGER DEFAULT 0,

        locked_until INTEGER DEFAULT NULL,

        created_at INTEGER NOT NULL

    );
`);


// =====================================================
// OTP CHALLENGES TABLE
// =====================================================

db.exec(`
    CREATE TABLE IF NOT EXISTS otp_challenges (

        challenge_id TEXT PRIMARY KEY,

        user_id TEXT NOT NULL,

        channel TEXT NOT NULL,

        otp_hash TEXT NOT NULL,

        created_at INTEGER NOT NULL,

        expires_at INTEGER NOT NULL,

        attempts INTEGER DEFAULT 0,

        verified INTEGER DEFAULT 0

    );
`);


console.log(
    "SQLite database initialized."
);


module.exports = db;