require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const helmet = require("helmet");
const path = require("path");

const {
    db,
    initializeDatabase
} = require("./database");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());
// =====================================================
// SETTINGS
// =====================================================

const MAX_OTP_ATTEMPTS = 5;
const MAX_LOGIN_ATTEMPTS = 5;

const OTP_EXPIRY = 5 * 60 * 1000;
const LOCKOUT_TIME = 5 * 60 * 1000;
const OTP_RESEND_COOLDOWN = 60 * 1000;

// =====================================================
// MIDDLEWARE
// =====================================================

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

app.use(
    cors({
        origin: true,
        credentials: true
    })
);

app.use(express.json());

app.use(
    session({
        secret:
            process.env.SESSION_SECRET ||
            "development-session-secret",

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure:
                process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 30 * 60 * 1000
        }
    })
);

app.use(
    express.static(
        path.join(__dirname, "../public")
    )
);

app.get("/", (req, res) => {

    res.sendFile(
        path.join(
            __dirname,
            "../public/index.html"
        )
    );
});

// =====================================================
// HELPERS
// =====================================================

function validatePassword(password) {

    if (!password || password.length < 8) {
        return "Password must be at least 8 characters long.";
    }

    if (!/[A-Z]/.test(password)) {
        return "Password must contain at least one uppercase letter.";
    }

    if (!/[a-z]/.test(password)) {
        return "Password must contain at least one lowercase letter.";
    }

    if (!/[0-9]/.test(password)) {
        return "Password must contain at least one number.";
    }

    if (!/[^A-Za-z0-9]/.test(password)) {
        return "Password must contain at least one special character.";
    }

    return null;
}

function isValidEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        email
    );
}

function isValidPhone(phone) {

    return /^[0-9]{10}$/.test(phone);
}

function isValidOTP(otp) {

    return /^[0-9]{6}$/.test(otp);
}

function generateOTP() {

    return crypto
        .randomInt(100000, 1000000)
        .toString();
}

function hashOTP(otp) {

    return crypto
        .createHash("sha256")
        .update(otp)
        .digest("hex");
}

// =====================================================
// DATABASE HELPERS
// =====================================================

async function findUserById(userId) {

    const result =
        await db.execute({
            sql: `
                SELECT *
                FROM users
                WHERE user_id = ?
            `,
            args: [userId]
        });

    return result.rows[0] || null;
}

async function findUserByEmail(email) {

    const result =
        await db.execute({
            sql: `
                SELECT *
                FROM users
                WHERE email = ?
            `,
            args: [email]
        });

    return result.rows[0] || null;
}

// =====================================================
// OTP CREATION
// =====================================================

async function createOTPChallenge(
    userId,
    channel
) {

    const existing =
        await db.execute({
            sql: `
                SELECT *
                FROM otp_challenges
                WHERE user_id = ?
                  AND channel = ?
                  AND created_at > ?
                  AND verified = 0
                ORDER BY created_at DESC
                LIMIT 1
            `,
            args: [
                userId,
                channel,
                Date.now() -
                    OTP_RESEND_COOLDOWN
            ]
        });

    if (existing.rows.length > 0) {

        const challenge =
            existing.rows[0];

        const retryAfter =
            Math.ceil(
                (
                    OTP_RESEND_COOLDOWN -
                    (
                        Date.now() -
                        Number(
                            challenge.created_at
                        )
                    )
                ) / 1000
            );

        return {
            cooldown: true,
            retryAfter
        };
    }

    const challengeId =
        crypto.randomUUID();

    const otp =
        generateOTP();

    const now =
        Date.now();

    const expiresAt =
        now + OTP_EXPIRY;

    const otpHash =
        hashOTP(otp);

    await db.execute({
        sql: `
            INSERT INTO otp_challenges
            (
                challenge_id,
                user_id,
                channel,
                otp_hash,
                created_at,
                expires_at,
                attempts,
                verified
            )
            VALUES (?, ?, ?, ?, ?, ?, 0, 0)
        `,
        args: [
            challengeId,
            userId,
            channel,
            otpHash,
            now,
            expiresAt
        ]
    });

    return {
        challengeId,
        otp
    };
}

// =====================================================
// OTP VERIFICATION
// =====================================================

async function verifyOTPChallenge(
    challengeId,
    otp,
    channel
) {

    const result =
        await db.execute({
            sql: `
                SELECT *
                FROM otp_challenges
                WHERE challenge_id = ?
            `,
            args: [challengeId]
        });

    const challenge =
        result.rows[0];

    if (!challenge) {

        return {
            success: false,
            status: 404,
            message:
                "OTP challenge not found."
        };
    }

    if (challenge.channel !== channel) {

        return {
            success: false,
            status: 400,
            message:
                "Invalid OTP challenge."
        };
    }

    if (Number(challenge.verified)) {

        return {
            success: false,
            status: 400,
            message:
                "This OTP has already been used."
        };
    }

    if (
        Date.now() >
        Number(challenge.expires_at)
    ) {

        return {
            success: false,
            status: 400,
            message:
                "OTP has expired."
        };
    }

    if (
        Number(challenge.attempts) >=
        MAX_OTP_ATTEMPTS
    ) {

        return {
            success: false,
            status: 429,
            message:
                "Maximum OTP attempts reached."
        };
    }

    const attempts =
        Number(challenge.attempts) + 1;

    await db.execute({
        sql: `
            UPDATE otp_challenges
            SET attempts = ?
            WHERE challenge_id = ?
        `,
        args: [
            attempts,
            challengeId
        ]
    });

    if (
        hashOTP(otp) !==
        challenge.otp_hash
    ) {

        return {
            success: false,
            status: 400,
            message:
                "Incorrect OTP.",
            attemptsRemaining:
                MAX_OTP_ATTEMPTS -
                attempts
        };
    }

    await db.execute({
        sql: `
            UPDATE otp_challenges
            SET verified = 1
            WHERE challenge_id = ?
        `,
        args: [challengeId]
    });

    return {
        success: true,
        challenge
    };
}

// =====================================================
// REGISTER
// =====================================================

app.post(
    "/api/register",
    async (req, res) => {

        try {

            const {
                name,
                email,
                phone,
                password
            } = req.body;

            if (
                !name ||
                !email ||
                !phone ||
                !password
            ) {

                return res.status(400).json({
                    message:
                        "All registration fields are required."
                });
            }

            const normalizedEmail =
                email.trim().toLowerCase();

            const normalizedPhone =
                phone.trim();

            if (
                !isValidEmail(
                    normalizedEmail
                )
            ) {

                return res.status(400).json({
                    message:
                        "Please enter a valid email address."
                });
            }

            if (
                !isValidPhone(
                    normalizedPhone
                )
            ) {

                return res.status(400).json({
                    message:
                        "Mobile number must contain exactly 10 digits."
                });
            }

            const passwordError =
                validatePassword(password);

            if (passwordError) {

                return res.status(400).json({
                    message:
                        passwordError
                });
            }

            const existingUser =
                await findUserByEmail(
                    normalizedEmail
                );

            if (existingUser) {

                return res.status(409).json({
                    message:
                        "An account with this email already exists."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    10
                );

            const userId =
                crypto.randomUUID();

            await db.execute({
                sql: `
                    INSERT INTO users
                    (
                        user_id,
                        name,
                        email,
                        phone,
                        password_hash,
                        email_verified,
                        sms_verified,
                        mfa_enabled,
                        failed_login_attempts,
                        locked_until,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, NULL, ?)
                `,
                args: [
                    userId,
                    name.trim(),
                    normalizedEmail,
                    normalizedPhone,
                    passwordHash,
                    Date.now()
                ]
            });

            const challenge =
                await createOTPChallenge(
                    userId,
                    "email"
                );

            if (challenge.cooldown) {

                return res.status(429).json({
                    message:
                        `Please wait ${challenge.retryAfter} seconds before requesting another OTP.`
                });
            }

            console.log("");
            console.log(
                "================================="
            );
            console.log(
                "[SIMULATED EMAIL]"
            );
            console.log(
                "To:",
                normalizedEmail
            );
            console.log(
                "OTP:",
                challenge.otp
            );
            console.log(
                "Expires in: 5 minutes"
            );
            console.log(
                "================================="
            );
            console.log("");

            const response = {

    message:
        "Registration started. Verify your email OTP.",

    challengeId:
        challenge.challengeId,

    userId
};



return res.status(201).json(response);
        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Server error during registration."
            });
        }
    }
);

// =====================================================
// SEND EMAIL OTP
// =====================================================

app.post(
    "/api/send-email-otp",
    async (req, res) => {

        try {

            const { email } =
                req.body;

            if (!email) {

                return res.status(400).json({
                    message:
                        "Email is required."
                });
            }

            const normalizedEmail =
                email.trim().toLowerCase();

            const user =
                await findUserByEmail(
                    normalizedEmail
                );

            if (!user) {

                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            const challenge =
                await createOTPChallenge(
                    user.user_id,
                    "email"
                );

            if (challenge.cooldown) {

                return res.status(429).json({
                    message:
                        `Please wait ${challenge.retryAfter} seconds before requesting another OTP.`
                });
            }

            console.log(
                "[SIMULATED EMAIL OTP]"
            );

            console.log(
                "To:",
                user.email
            );

            console.log(
                "OTP:",
                challenge.otp
            );

          return res.json({

    message:
        "Email OTP sent successfully.",

    challengeId:
        challenge.challengeId

});

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to send email OTP."
            });
        }
    }
);

// =====================================================
// RESEND EMAIL OTP
// =====================================================

app.post(
    "/api/resend-email-otp",
    async (req, res) => {

        try {

            const { email } =
                req.body;

            if (!email) {

                return res.status(400).json({
                    message:
                        "Email is required."
                });
            }

            const normalizedEmail =
                email.trim().toLowerCase();

            const user =
                await findUserByEmail(
                    normalizedEmail
                );

            if (!user) {

                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            const challenge =
                await createOTPChallenge(
                    user.user_id,
                    "email"
                );

            if (challenge.cooldown) {

                return res.status(429).json({
                    message:
                        `Please wait ${challenge.retryAfter} seconds before requesting another OTP.`
                });
            }

            console.log(
                "[SIMULATED EMAIL OTP RESEND]"
            );

            console.log(
                "To:",
                user.email
            );

            console.log(
                "OTP:",
                challenge.otp
            );

            return res.json({

                message:
                    "A new email OTP has been sent.",

                challengeId:
                    challenge.challengeId
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to resend OTP."
            });
        }
    }
);

// =====================================================
// VERIFY EMAIL OTP
// =====================================================

app.post(
    "/api/verify-email-otp",
    async (req, res) => {

        try {

            const {
                challengeId,
                otp
            } = req.body;

            if (!isValidOTP(otp)) {

                return res.status(400).json({
                    message:
                        "OTP must contain exactly 6 digits."
                });
            }

            const result =
                await verifyOTPChallenge(
                    challengeId,
                    otp,
                    "email"
                );

            if (!result.success) {

                return res
                    .status(result.status)
                    .json({
                        message:
                            result.message,

                        attemptsRemaining:
                            result.attemptsRemaining
                    });
            }

            const user =
                await findUserById(
                    result.challenge.user_id
                );

            if (!user) {

                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            await db.execute({
                sql: `
                    UPDATE users
                    SET email_verified = 1
                    WHERE user_id = ?
                `,
                args: [user.user_id]
            });

            return res.json({

                message:
                    "Email verified successfully.",

                userId:
                    user.user_id
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to verify email OTP."
            });
        }
    }
);

// =====================================================
// SEND SMS OTP
// =====================================================

app.post(
    "/api/send-sms-otp",
    async (req, res) => {

        try {

            const { userId } =
                req.body;

            if (!userId) {

                return res.status(400).json({
                    message:
                        "User ID is required."
                });
            }

            const user =
                await findUserById(
                    userId
                );

            if (!user) {

                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            if (!Number(user.email_verified)) {

                return res.status(403).json({
                    message:
                        "Please verify your email first."
                });
            }

            const challenge =
                await createOTPChallenge(
                    user.user_id,
                    "sms"
                );

            if (challenge.cooldown) {

                return res.status(429).json({
                    message:
                        `Please wait ${challenge.retryAfter} seconds before requesting another OTP.`
                });
            }

            console.log(
                "[SIMULATED SMS]"
            );

            console.log(
                "To:",
                user.phone
            );

            console.log(
                "OTP:",
                challenge.otp
            );

            return res.json({

                message:
                    "SMS OTP sent successfully.",

                challengeId:
                    challenge.challengeId
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to send SMS OTP."
            });
        }
    }
);

// =====================================================
// VERIFY SMS OTP
// =====================================================

app.post(
    "/api/verify-sms-otp",
    async (req, res) => {

        try {

            const {
                challengeId,
                otp
            } = req.body;

            if (!isValidOTP(otp)) {

                return res.status(400).json({
                    message:
                        "OTP must contain exactly 6 digits."
                });
            }

            const result =
                await verifyOTPChallenge(
                    challengeId,
                    otp,
                    "sms"
                );

            if (!result.success) {

                return res
                    .status(result.status)
                    .json({
                        message:
                            result.message,

                        attemptsRemaining:
                            result.attemptsRemaining
                    });
            }

            const user =
                await findUserById(
                    result.challenge.user_id
                );

            if (!user) {

                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            await db.execute({
                sql: `
                    UPDATE users
                    SET
                        sms_verified = 1,
                        mfa_enabled = 1
                    WHERE user_id = ?
                `,
                args: [user.user_id]
            });

            return res.json({

                message:
                    "SMS verified successfully. MFA enabled.",

                userId:
                    user.user_id,

                mfaEnabled: true
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to verify SMS OTP."
            });
        }
    }
);

// =====================================================
// LOGIN
// =====================================================

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            if (!email || !password) {

                return res.status(400).json({
                    message:
                        "Email and password are required."
                });
            }

            const normalizedEmail =
                email.trim().toLowerCase();

            const user =
                await findUserByEmail(
                    normalizedEmail
                );

            if (!user) {

                return res.status(401).json({
                    message:
                        "Invalid email or password."
                });
            }

            if (
                user.locked_until &&
                Date.now() <
                Number(user.locked_until)
            ) {

                return res.status(423).json({
                    message:
                        "Account temporarily locked."
                });
            }

            const correct =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!correct) {

                const failedAttempts =
                    Number(
                        user.failed_login_attempts
                    ) + 1;

                if (
                    failedAttempts >=
                    MAX_LOGIN_ATTEMPTS
                ) {

                    const lockedUntil =
                        Date.now() +
                        LOCKOUT_TIME;

                    await db.execute({
                        sql: `
                            UPDATE users
                            SET
                                failed_login_attempts = 0,
                                locked_until = ?
                            WHERE user_id = ?
                        `,
                        args: [
                            lockedUntil,
                            user.user_id
                        ]
                    });

                    return res.status(423).json({
                        message:
                            "Too many failed attempts. Account temporarily locked for 5 minutes."
                    });
                }

                await db.execute({
                    sql: `
                        UPDATE users
                        SET failed_login_attempts = ?
                        WHERE user_id = ?
                    `,
                    args: [
                        failedAttempts,
                        user.user_id
                    ]
                });

                return res.status(401).json({

                    message:
                        "Invalid email or password.",

                    attemptsRemaining:
                        MAX_LOGIN_ATTEMPTS -
                        failedAttempts
                });
            }

            await db.execute({
                sql: `
                    UPDATE users
                    SET failed_login_attempts = 0
                    WHERE user_id = ?
                `,
                args: [user.user_id]
            });

            if (!Number(user.email_verified)) {

                return res.status(403).json({
                    message:
                        "Please verify your email first."
                });
            }

            if (!Number(user.mfa_enabled)) {

                return res.status(403).json({
                    message:
                        "MFA is not enabled."
                });
            }

            const challenge =
                await createOTPChallenge(
                    user.user_id,
                    "login"
                );

            if (challenge.cooldown) {

                return res.status(429).json({
                    message:
                        `Please wait ${challenge.retryAfter} seconds before requesting another OTP.`
                });
            }

            console.log(
                "[SIMULATED LOGIN EMAIL]"
            );

            console.log(
                "To:",
                user.email
            );

            console.log(
                "OTP:",
                challenge.otp
            );

            return res.json({

                message:
                    "Credentials valid. MFA verification required.",

                mfaRequired: true,

                challengeId:
                    challenge.challengeId
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Server error during login."
            });
        }
    }
);

// =====================================================
// VERIFY LOGIN OTP
// =====================================================

app.post(
    "/api/verify-login-otp",
    async (req, res) => {

        try {

            const {
                challengeId,
                otp
            } = req.body;

            if (!isValidOTP(otp)) {

                return res.status(400).json({
                    message:
                        "OTP must contain exactly 6 digits."
                });
            }

            const result =
                await verifyOTPChallenge(
                    challengeId,
                    otp,
                    "login"
                );

            if (!result.success) {

                return res
                    .status(result.status)
                    .json({

                        message:
                            result.message,

                        attemptsRemaining:
                            result.attemptsRemaining
                    });
            }

            const user =
                await findUserById(
                    result.challenge.user_id
                );

            if (!user) {

                return res.status(404).json({
                    message:
                        "User not found."
                });
            }

            req.session.userId =
                user.user_id;

            req.session.email =
                user.email;

            req.session.save(
                (error) => {

                    if (error) {

                        console.error(
                            "Session save error:",
                            error
                        );

                        return res.status(500).json({
                            message:
                                "Unable to create login session."
                        });
                    }

                    return res.json({

                        message:
                            "Login successful.",

                        authenticated:
                            true,

                        user: {

                            userId:
                                user.user_id,

                            name:
                                user.name,

                            email:
                                user.email
                        }
                    });
                }
            );

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to verify login OTP."
            });
        }
    }
);

// =====================================================
// SESSION AUTHENTICATION
// =====================================================

function requireAuthentication(
    req,
    res,
    next
) {

    if (!req.session.userId) {

        return res.status(401).json({
            message:
                "Authentication required."
        });
    }

    next();
}

// =====================================================
// CURRENT USER
// =====================================================

app.get(
    "/api/me",
    requireAuthentication,
    async (req, res) => {

        try {

            const user =
                await findUserById(
                    req.session.userId
                );

            if (!user) {

                req.session.destroy(
                    () => {}
                );

                return res.status(401).json({
                    message:
                        "User session is invalid."
                });
            }

            return res.json({

                authenticated: true,

                user: {

                    userId:
                        user.user_id,

                    name:
                        user.name,

                    email:
                        user.email,

                    phone:
                        user.phone,

                    mfaEnabled:
                        Boolean(
                            Number(
                                user.mfa_enabled
                            )
                        )
                }
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to load current user."
            });
        }
    }
);

// =====================================================
// LOGOUT
// =====================================================

app.post(
    "/api/logout",
    (req, res) => {

        req.session.destroy(
            (error) => {

                if (error) {

                    return res.status(500).json({
                        message:
                            "Logout failed."
                    });
                }

                res.clearCookie(
                    "connect.sid"
                );

                return res.json({
                    message:
                        "Logged out successfully."
                });
            }
        );
    }
);

// =====================================================
// FORGOT PASSWORD
// =====================================================

app.post(
    "/api/forgot-password",
    async (req, res) => {

        try {

            const { email } =
                req.body;

            if (!email) {

                return res.status(400).json({
                    message:
                        "Email is required."
                });
            }

            const normalizedEmail =
                email.trim().toLowerCase();

            const user =
                await findUserByEmail(
                    normalizedEmail
                );

            if (!user) {

                return res.json({
                    message:
                        "If an account exists, a password reset OTP has been sent."
                });
            }

            const challenge =
                await createOTPChallenge(
                    user.user_id,
                    "reset"
                );

            if (challenge.cooldown) {

                return res.status(429).json({
                    message:
                        `Please wait ${challenge.retryAfter} seconds before requesting another OTP.`
                });
            }

            console.log(
                "[SIMULATED PASSWORD RESET EMAIL]"
            );

            console.log(
                "To:",
                user.email
            );

            console.log(
                "OTP:",
                challenge.otp
            );

            return res.json({

                message:
                    "Password reset OTP sent.",

                challengeId:
                    challenge.challengeId
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to send password reset OTP."
            });
        }
    }
);

// =====================================================
// VERIFY RESET OTP
// =====================================================

app.post(
    "/api/verify-reset-otp",
    async (req, res) => {

        try {

            const {
                challengeId,
                otp
            } = req.body;

            if (!isValidOTP(otp)) {

                return res.status(400).json({
                    message:
                        "OTP must contain exactly 6 digits."
                });
            }

            const result =
                await verifyOTPChallenge(
                    challengeId,
                    otp,
                    "reset"
                );

            if (!result.success) {

                return res
                    .status(result.status)
                    .json({

                        message:
                            result.message,

                        attemptsRemaining:
                            result.attemptsRemaining
                    });
            }

            return res.json({

                message:
                    "OTP verified successfully.",

                resetToken:
                    challengeId
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to verify reset OTP."
            });
        }
    }
);

// =====================================================
// RESET PASSWORD
// =====================================================

app.post(
    "/api/reset-password",
    async (req, res) => {

        try {

            const {
                resetToken,
                newPassword
            } = req.body;

            if (
                !resetToken ||
                !newPassword
            ) {

                return res.status(400).json({
                    message:
                        "Reset token and new password are required."
                });
            }

            const passwordError =
                validatePassword(
                    newPassword
                );

            if (passwordError) {

                return res.status(400).json({
                    message:
                        passwordError
                });
            }

            const result =
                await db.execute({
                    sql: `
                        SELECT *
                        FROM otp_challenges
                        WHERE challenge_id = ?
                    `,
                    args: [resetToken]
                });

            const challenge =
                result.rows[0];

            if (!challenge) {

                return res.status(404).json({
                    message:
                        "Password reset session not found."
                });
            }

            if (
                challenge.channel !==
                "reset"
            ) {

                return res.status(400).json({
                    message:
                        "Invalid password reset session."
                });
            }

            if (
                !Number(challenge.verified)
            ) {

                return res.status(403).json({
                    message:
                        "Please verify the reset OTP first."
                });
            }

            if (
                Date.now() >
                Number(challenge.expires_at)
            ) {

                return res.status(400).json({
                    message:
                        "Password reset session has expired."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    newPassword,
                    10
                );

            await db.execute({
                sql: `
                    UPDATE users
                    SET
                        password_hash = ?,
                        failed_login_attempts = 0,
                        locked_until = NULL
                    WHERE user_id = ?
                `,
                args: [
                    passwordHash,
                    challenge.user_id
                ]
            });

            await db.execute({
                sql: `
                    DELETE FROM otp_challenges
                    WHERE challenge_id = ?
                `,
                args: [resetToken]
            });

            return res.json({
                message:
                    "Password reset successfully."
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Server error while resetting password."
            });
        }
    }
);

// =====================================================
// JWT TOKEN
// =====================================================

app.post(
    "/api/token",
    requireAuthentication,
    async (req, res) => {

        try {

            const user =
                await findUserById(
                    req.session.userId
                );

            if (!user) {

                return res.status(401).json({
                    message:
                        "Authentication required."
                });
            }

            if (!process.env.JWT_SECRET) {

                return res.status(500).json({
                    message:
                        "JWT secret is not configured."
                });
            }

            const token =
                jwt.sign(
                    {
                        userId:
                            user.user_id,

                        email:
                            user.email
                    },

                    process.env.JWT_SECRET,

                    {
                        expiresIn:
                            "15m"
                    }
                );

            return res.json({

                message:
                    "JWT issued successfully.",

                token,

                expiresIn:
                    "15 minutes"
            });

        } catch (error) {

            console.error(error);

            return res.status(500).json({
                message:
                    "Unable to create JWT."
            });
        }
    }
);

// =====================================================
// JWT PROTECTED API
// =====================================================

app.get(
    "/api/protected",
    async (req, res) => {

        const authHeader =
            req.headers.authorization;

        if (
            !authHeader ||
            !authHeader.startsWith(
                "Bearer "
            )
        ) {

            return res.status(401).json({
                message:
                    "JWT authorization required."
            });
        }

        const token =
            authHeader.substring(7);

        if (!process.env.JWT_SECRET) {

            return res.status(500).json({
                message:
                    "JWT secret is not configured."
            });
        }

        try {

            const decoded =
                jwt.verify(
                    token,
                    process.env.JWT_SECRET
                );

            const user =
                await findUserById(
                    decoded.userId
                );

            if (!user) {

                return res.status(401).json({
                    message:
                        "User associated with JWT was not found."
                });
            }

            return res.json({

                message:
                    "JWT authentication successful.",

                authenticated:
                    true,

                user: {

                    userId:
                        user.user_id,

                    name:
                        user.name,

                    email:
                        user.email
                }
            });

        } catch (error) {

            return res.status(401).json({
                message:
                    "Invalid or expired JWT."
            });
        }
    }
);

// =====================================================
// TEST API
// =====================================================

app.get(
    "/api/test",
    (req, res) => {

        return res.json({
            message:
                "Backend is working!"
        });
    }
);

// =====================================================
// START SERVER
// =====================================================

async function startServer() {

    try {

        await initializeDatabase();

        const PORT =
            process.env.PORT || 3000;

        app.listen(
            PORT,
            () => {

                console.log(
                    `Server running at http://localhost:${PORT}`
                );
            }
        );

    } catch (error) {

        console.error(
            "Database initialization failed:",
            error
        );

        process.exit(1);
    }
}

startServer();