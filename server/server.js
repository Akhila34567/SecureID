require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const session = require("express-session");
const helmet = require("helmet");
const path = require("path");

const db = require("./database");

const app = express();


// =====================================================
// SECURITY SETTINGS
// =====================================================

const MAX_OTP_ATTEMPTS = 5;

const MAX_LOGIN_ATTEMPTS = 5;

const OTP_EXPIRY =
    5 * 60 * 1000;

const LOCKOUT_TIME =
    5 * 60 * 1000;

const OTP_RESEND_COOLDOWN =
    60 * 1000;


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
        origin: "http://localhost:3000",
        credentials: true
    })
);

app.use(express.json());

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            secure: false,
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
// PASSWORD VALIDATION
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


// =====================================================
// INPUT VALIDATION
// =====================================================

function isValidEmail(email) {

    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
        .test(email);

}


function isValidPhone(phone) {

    return /^[0-9]{10}$/
        .test(phone);

}


function isValidOTP(otp) {

    return /^[0-9]{6}$/
        .test(otp);

}


// =====================================================
// OTP FUNCTIONS
// =====================================================

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
// DATABASE USER HELPERS
// =====================================================

function findUserById(userId) {

    return db
        .prepare(
            `
            SELECT *
            FROM users
            WHERE user_id = ?
            `
        )
        .get(userId);

}


function findUserByEmail(email) {

    return db
        .prepare(
            `
            SELECT *
            FROM users
            WHERE email = ?
            `
        )
        .get(email);

}


// =====================================================
// OTP CHALLENGE CREATION
// =====================================================

function createOTPChallenge(
    userId,
    channel
) {

    const existingChallenge =
        db
            .prepare(
                `
                SELECT *
                FROM otp_challenges
                WHERE user_id = ?
                  AND channel = ?
                  AND created_at > ?
                  AND verified = 0
                ORDER BY created_at DESC
                LIMIT 1
                `
            )
            .get(
                userId,
                channel,
                Date.now() -
                    OTP_RESEND_COOLDOWN
            );


    if (existingChallenge) {

        const retryAfter =
            Math.ceil(
                (
                    OTP_RESEND_COOLDOWN -
                    (
                        Date.now() -
                        existingChallenge.created_at
                    )
                ) / 1000
            );

        return {

            cooldown: true,

            retryAfter

        };

    }


    const otp =
        generateOTP();


    const challengeId =
        crypto.randomUUID();


    const now =
        Date.now();


    const expiresAt =
        now + OTP_EXPIRY;


    const otpHash =
        hashOTP(otp);


    db
        .prepare(
            `
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
            `
        )
        .run(
            challengeId,
            userId,
            channel,
            otpHash,
            now,
            expiresAt
        );


    return {

        challengeId,

        otp

    };

}


// =====================================================
// VERIFY OTP CHALLENGE
// =====================================================

function verifyOTPChallenge(
    challengeId,
    otp,
    channel
) {

    const challenge =
        db
            .prepare(
                `
                SELECT *
                FROM otp_challenges
                WHERE challenge_id = ?
                `
            )
            .get(challengeId);


    if (!challenge) {

        return {

            success: false,

            status: 404,

            message:
                "OTP challenge not found."

        };

    }


    if (
        challenge.channel !==
        channel
    ) {

        return {

            success: false,

            status: 400,

            message:
                "Invalid OTP challenge."

        };

    }


    if (
        challenge.verified
    ) {

        return {

            success: false,

            status: 400,

            message:
                "This OTP has already been used."

        };

    }


    if (
        Date.now() >
        challenge.expires_at
    ) {

        return {

            success: false,

            status: 400,

            message:
                "OTP has expired."

        };

    }


    if (
        challenge.attempts >=
        MAX_OTP_ATTEMPTS
    ) {

        return {

            success: false,

            status: 429,

            message:
                "Maximum OTP attempts reached."

        };

    }


    const newAttempts =
        challenge.attempts + 1;


    db
        .prepare(
            `
            UPDATE otp_challenges
            SET attempts = ?
            WHERE challenge_id = ?
            `
        )
        .run(
            newAttempts,
            challengeId
        );


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
                newAttempts

        };

    }


    db
        .prepare(
            `
            UPDATE otp_challenges
            SET verified = 1
            WHERE challenge_id = ?
            `
        )
        .run(challengeId);


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
                email
                    .trim()
                    .toLowerCase();


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
                validatePassword(
                    password
                );


            if (passwordError) {

                return res.status(400).json({

                    message:
                        passwordError

                });

            }


            const existingUser =
                findUserByEmail(
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


            db
                .prepare(
                    `
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
                    `
                )
                .run(
                    userId,
                    name.trim(),
                    normalizedEmail,
                    normalizedPhone,
                    passwordHash,
                    Date.now()
                );


            const emailChallenge =
                createOTPChallenge(
                    userId,
                    "email"
                );


            if (
                emailChallenge.cooldown
            ) {

                return res.status(429).json({

                    message:
                        `Please wait ${emailChallenge.retryAfter} seconds before requesting another OTP.`

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
                emailChallenge.otp
            );

            console.log(
                "Expires in: 5 minutes"
            );

            console.log(
                "================================="
            );

            console.log("");


            return res.status(201).json({

                message:
                    "Registration started. Verify your email OTP.",

                challengeId:
                    emailChallenge.challengeId,

                userId

            });


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
// RESEND EMAIL OTP
// =====================================================

app.post(
    "/api/resend-email-otp",
    (req, res) => {

        const {
            email
        } = req.body;


        if (!email) {

            return res.status(400).json({

                message:
                    "Email is required."

            });

        }


        const normalizedEmail =
            email
                .trim()
                .toLowerCase();


        const user =
            findUserByEmail(
                normalizedEmail
            );


        if (!user) {

            return res.status(404).json({

                message:
                    "User not found."

            });

        }


        const challenge =
            createOTPChallenge(
                user.user_id,
                "email"
            );


        if (
            challenge.cooldown
        ) {

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

        console.log(
            "Expires in: 5 minutes"
        );

        console.log(
            "================================="
        );

        console.log("");


        return res.json({

            message:
                "A new email OTP has been sent.",

            challengeId:
                challenge.challengeId

        });

    }
);


// =====================================================
// VERIFY EMAIL OTP
// =====================================================

app.post(
    "/api/verify-email-otp",
    (req, res) => {

        const {
            challengeId,
            otp
        } = req.body;


        if (
            !isValidOTP(otp)
        ) {

            return res.status(400).json({

                message:
                    "OTP must contain exactly 6 digits."

            });

        }


        const result =
            verifyOTPChallenge(
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
            findUserById(
                result.challenge.user_id
            );


        if (!user) {

            return res.status(404).json({

                message:
                    "User not found."

            });

        }


        db
            .prepare(
                `
                UPDATE users
                SET email_verified = 1
                WHERE user_id = ?
                `
            )
            .run(user.user_id);


        return res.json({

            message:
                "Email verified successfully.",

            userId:
                user.user_id

        });

    }
);


// =====================================================
// SEND SMS OTP
// =====================================================

app.post(
    "/api/send-sms-otp",
    (req, res) => {

        const {
            userId
        } = req.body;


        if (!userId) {

            return res.status(400).json({

                message:
                    "User ID is required."

            });

        }


        const user =
            findUserById(
                userId
            );


        if (!user) {

            return res.status(404).json({

                message:
                    "User not found."

            });

        }


        if (
            !user.email_verified
        ) {

            return res.status(403).json({

                message:
                    "Please verify your email first."

            });

        }


        const challenge =
            createOTPChallenge(
                user.user_id,
                "sms"
            );


        if (
            challenge.cooldown
        ) {

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

        console.log(
            "Expires in: 5 minutes"
        );

        console.log(
            "================================="
        );

        console.log("");


        return res.json({

            message:
                "SMS OTP sent successfully.",

            challengeId:
                challenge.challengeId

        });

    }
);


// =====================================================
// VERIFY SMS OTP
// =====================================================

app.post(
    "/api/verify-sms-otp",
    (req, res) => {

        const {
            challengeId,
            otp
        } = req.body;


        if (
            !isValidOTP(otp)
        ) {

            return res.status(400).json({

                message:
                    "OTP must contain exactly 6 digits."

            });

        }


        const result =
            verifyOTPChallenge(
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
            findUserById(
                result.challenge.user_id
            );


        if (!user) {

            return res.status(404).json({

                message:
                    "User not found."

            });

        }


        db
            .prepare(
                `
                UPDATE users
                SET
                    sms_verified = 1,
                    mfa_enabled = 1
                WHERE user_id = ?
                `
            )
            .run(user.user_id);


        return res.json({

            message:
                "SMS verified successfully. MFA enabled.",

            userId:
                user.user_id,

            mfaEnabled:
                true

        });

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


            if (
                !email ||
                !password
            ) {

                return res.status(400).json({

                    message:
                        "Email and password are required."

                });

            }


            const normalizedEmail =
                email
                    .trim()
                    .toLowerCase();


            const user =
                findUserByEmail(
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
                    user.locked_until
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
                    user.failed_login_attempts + 1;


                if (
                    failedAttempts >=
                    MAX_LOGIN_ATTEMPTS
                ) {

                    const lockedUntil =
                        Date.now() +
                        LOCKOUT_TIME;


                    db
                        .prepare(
                            `
                            UPDATE users
                            SET
                                failed_login_attempts = 0,
                                locked_until = ?
                            WHERE user_id = ?
                            `
                        )
                        .run(
                            lockedUntil,
                            user.user_id
                        );


                    return res.status(423).json({

                        message:
                            "Too many failed attempts. Account temporarily locked for 5 minutes."

                    });

                }


                db
                    .prepare(
                        `
                        UPDATE users
                        SET failed_login_attempts = ?
                        WHERE user_id = ?
                        `
                    )
                    .run(
                        failedAttempts,
                        user.user_id
                    );


                return res.status(401).json({

                    message:
                        "Invalid email or password.",

                    attemptsRemaining:
                        MAX_LOGIN_ATTEMPTS -
                        failedAttempts

                });

            }


            db
                .prepare(
                    `
                    UPDATE users
                    SET failed_login_attempts = 0
                    WHERE user_id = ?
                    `
                )
                .run(user.user_id);


            if (
                !user.email_verified
            ) {

                return res.status(403).json({

                    message:
                        "Please verify your email first."

                });

            }


            if (
                !user.mfa_enabled
            ) {

                return res.status(403).json({

                    message:
                        "MFA is not enabled."

                });

            }


            const challenge =
                createOTPChallenge(
                    user.user_id,
                    "login"
                );


            if (
                challenge.cooldown
            ) {

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

            console.log(
                "Expires in: 5 minutes"
            );

            console.log(
                "================================="
            );

            console.log("");


            return res.json({

                message:
                    "Credentials valid. MFA verification required.",

                mfaRequired:
                    true,

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
    (req, res) => {

        const {
            challengeId,
            otp
        } = req.body;


        if (
            !isValidOTP(otp)
        ) {

            return res.status(400).json({

                message:
                    "OTP must contain exactly 6 digits."

            });

        }


        const result =
            verifyOTPChallenge(
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
            findUserById(
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


// =====================================================
// AUTHENTICATION MIDDLEWARE
// =====================================================

function requireAuthentication(
    req,
    res,
    next
) {

    if (
        !req.session.userId
    ) {

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
    (req, res) => {

        const user =
            findUserById(
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

            authenticated:
                true,

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
                        user.mfa_enabled
                    )

            }

        });

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
    (req, res) => {

        const {
            email
        } = req.body;


        if (!email) {

            return res.status(400).json({

                message:
                    "Email is required."

            });

        }


        const normalizedEmail =
            email
                .trim()
                .toLowerCase();


        const user =
            findUserByEmail(
                normalizedEmail
            );


        // Do not reveal whether account exists.
        if (!user) {

            return res.json({

                message:
                    "If an account exists, a password reset OTP has been sent."

            });

        }


        const resetChallenge =
            createOTPChallenge(
                user.user_id,
                "reset"
            );


        if (
            resetChallenge.cooldown
        ) {

            return res.status(429).json({

                message:
                    `Please wait ${resetChallenge.retryAfter} seconds before requesting another OTP.`

            });

        }


        console.log("");

        console.log(
            "================================="
        );

        console.log(
            "[SIMULATED PASSWORD RESET EMAIL]"
        );

        console.log(
            "To:",
            user.email
        );

        console.log(
            "OTP:",
            resetChallenge.otp
        );

        console.log(
            "Expires in: 5 minutes"
        );

        console.log(
            "================================="
        );

        console.log("");


        return res.json({

            message:
                "Password reset OTP sent.",

            challengeId:
                resetChallenge.challengeId

        });

    }
);


// =====================================================
// VERIFY PASSWORD RESET OTP
// =====================================================

app.post(
    "/api/verify-reset-otp",
    (req, res) => {

        const {
            challengeId,
            otp
        } = req.body;


        if (
            !isValidOTP(otp)
        ) {

            return res.status(400).json({

                message:
                    "OTP must contain exactly 6 digits."

            });

        }


        const result =
            verifyOTPChallenge(
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


            const challenge =
                db
                    .prepare(
                        `
                        SELECT *
                        FROM otp_challenges
                        WHERE challenge_id = ?
                        `
                    )
                    .get(resetToken);


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
                !challenge.verified
            ) {

                return res.status(403).json({

                    message:
                        "Please verify the reset OTP first."

                });

            }


            if (
                Date.now() >
                challenge.expires_at
            ) {

                return res.status(400).json({

                    message:
                        "Password reset session has expired."

                });

            }


            const user =
                findUserById(
                    challenge.user_id
                );


            if (!user) {

                return res.status(404).json({

                    message:
                        "User not found."

                });

            }


            const passwordHash =
                await bcrypt.hash(
                    newPassword,
                    10
                );


            db
                .prepare(
                    `
                    UPDATE users
                    SET
                        password_hash = ?,
                        failed_login_attempts = 0,
                        locked_until = NULL
                    WHERE user_id = ?
                    `
                )
                .run(
                    passwordHash,
                    user.user_id
                );


            db
                .prepare(
                    `
                    DELETE FROM otp_challenges
                    WHERE challenge_id = ?
                    `
                )
                .run(resetToken);


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
// TEST API
// =====================================================

app.get(
    "/api/test",
    (req, res) => {

        res.json({

            message:
                "Backend is working!"

        });

    }
);


// =====================================================
// START SERVER
// =====================================================

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