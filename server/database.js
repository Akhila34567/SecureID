const { createClient } = require("@libsql/client");

const db = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN
});

// =====================================================
// INITIALIZE DATABASE
// =====================================================

async function initializeDatabase() {

    if (
        !process.env.TURSO_DATABASE_URL ||
        !process.env.TURSO_AUTH_TOKEN
    ) {
        throw new Error(
            "TURSO_DATABASE_URL and TURSO_AUTH_TOKEN are required."
        );
    }

    await db.batch(
        [
            {
                sql: `
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

                    )
                `,
                args: []
            },

            {
                sql: `
                    CREATE TABLE IF NOT EXISTS otp_challenges (

                        challenge_id TEXT PRIMARY KEY,

                        user_id TEXT NOT NULL,

                        channel TEXT NOT NULL,

                        otp_hash TEXT NOT NULL,

                        created_at INTEGER NOT NULL,

                        expires_at INTEGER NOT NULL,

                        attempts INTEGER DEFAULT 0,

                        verified INTEGER DEFAULT 0

                    )
                `,
                args: []
            }
        ],
        "write"
    );

    console.log(
        "Turso database initialized."
    );
}

module.exports = {
    db,
    initializeDatabase
};