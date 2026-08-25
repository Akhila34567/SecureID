const loginScreen =
    document.getElementById("loginScreen");

const registrationScreen =
    document.getElementById("registrationScreen");

const emailOTPScreen =
    document.getElementById("emailOTPScreen");

const smsOTPScreen =
    document.getElementById("smsOTPScreen");

const successScreen =
    document.getElementById("successScreen");

const loginOTPScreen =
    document.getElementById("loginOTPScreen");

const dashboardScreen =
    document.getElementById("dashboardScreen");

const forgotPasswordScreen =
    document.getElementById("forgotPasswordScreen");

const resetOTPScreen =
    document.getElementById("resetOTPScreen");

const newPasswordScreen =
    document.getElementById("newPasswordScreen");


// =====================================================
// SCREEN FUNCTIONS
// =====================================================

function hideAllScreens() {

    loginScreen.classList.add("hidden");
    registrationScreen.classList.add("hidden");
    emailOTPScreen.classList.add("hidden");
    smsOTPScreen.classList.add("hidden");
    successScreen.classList.add("hidden");
    loginOTPScreen.classList.add("hidden");
    dashboardScreen.classList.add("hidden");
    forgotPasswordScreen.classList.add("hidden");
    resetOTPScreen.classList.add("hidden");
    newPasswordScreen.classList.add("hidden");

}


function showLogin() {

    hideAllScreens();

    loginScreen.classList.remove("hidden");

}


function showRegistration() {

    hideAllScreens();

    registrationScreen.classList.remove("hidden");

}


function showEmailOTP() {

    hideAllScreens();

    emailOTPScreen.classList.remove("hidden");

}


function showSMSOTP() {

    hideAllScreens();

    smsOTPScreen.classList.remove("hidden");

}


function showSuccess() {

    hideAllScreens();

    successScreen.classList.remove("hidden");

}


function showLoginOTP() {

    hideAllScreens();

    loginOTPScreen.classList.remove("hidden");

}


function showDashboard() {

    hideAllScreens();

    dashboardScreen.classList.remove("hidden");

}


function showForgotPassword() {

    hideAllScreens();

    forgotPasswordScreen.classList.remove("hidden");

}


function showResetOTP() {

    hideAllScreens();

    resetOTPScreen.classList.remove("hidden");

}


function showNewPassword() {

    hideAllScreens();

    newPasswordScreen.classList.remove("hidden");

}


// =====================================================
// LOGIN → REGISTRATION
// =====================================================

document
    .getElementById("createAccount")
    .addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            showRegistration();

        }
    );


// =====================================================
// FORGOT PASSWORD
// =====================================================

document
    .getElementById("forgotPassword")
    .addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            showForgotPassword();

        }
    );


// =====================================================
// BACK TO LOGIN FROM FORGOT PASSWORD
// =====================================================

document
    .getElementById("backToLoginFromForgot")
    .addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            showLogin();

        }
    );


// =====================================================
// SEND PASSWORD RESET OTP
// =====================================================

document
    .getElementById("sendResetOTP")
    .addEventListener(
        "click",
        async function () {

            const email =
                document
                    .getElementById("forgotEmail")
                    .value
                    .trim();

            const message =
                document.getElementById(
                    "forgotPasswordMessage"
                );


            message.textContent = "";


            if (!email) {

                message.textContent =
                    "Please enter your email.";

                return;

            }


            message.textContent =
                "Sending verification code...";


            try {

                const response =
                    await fetch(
                        "/api/forgot-password",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    email
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "Unable to send code.";

                    return;

                }


                if (data.challengeId) {

                    sessionStorage.setItem(
                        "resetChallengeId",
                        data.challengeId
                    );

                    showResetOTP();

                } else {

                    message.textContent =
                        data.message;

                }


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// VERIFY RESET OTP
// =====================================================

document
    .getElementById("verifyResetOTP")
    .addEventListener(
        "click",
        async function () {

            const otp =
                document
                    .getElementById("resetOTP")
                    .value
                    .trim();


            const challengeId =
                sessionStorage.getItem(
                    "resetChallengeId"
                );


            const message =
                document.getElementById(
                    "resetOTPMessage"
                );


            if (!/^\d{6}$/.test(otp)) {

                message.textContent =
                    "Enter a valid 6-digit OTP.";

                return;

            }


            if (!challengeId) {

                message.textContent =
                    "Reset session expired. Please try again.";

                return;

            }


            message.textContent =
                "Verifying code...";


            try {

                const response =
                    await fetch(
                        "/api/verify-reset-otp",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    challengeId,
                                    otp
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "Invalid OTP.";

                    return;

                }


                sessionStorage.setItem(
                    "resetToken",
                    data.resetToken
                );


                showNewPassword();


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// RESET PASSWORD
// =====================================================

document
    .getElementById("resetPasswordButton")
    .addEventListener(
        "click",
        async function () {

            const newPassword =
                document
                    .getElementById("newPassword")
                    .value;


            const confirmPassword =
                document
                    .getElementById("confirmPassword")
                    .value;


            const resetToken =
                sessionStorage.getItem(
                    "resetToken"
                );


            const message =
                document.getElementById(
                    "resetPasswordMessage"
                );


            message.textContent = "";


            // PASSWORD LENGTH

            if (newPassword.length < 8) {

                message.textContent =
                    "Password must be at least 8 characters long.";

                return;

            }


            // UPPERCASE

            if (!/[A-Z]/.test(newPassword)) {

                message.textContent =
                    "Password must contain at least one uppercase letter.";

                return;

            }


            // LOWERCASE

            if (!/[a-z]/.test(newPassword)) {

                message.textContent =
                    "Password must contain at least one lowercase letter.";

                return;

            }


            // NUMBER

            if (!/[0-9]/.test(newPassword)) {

                message.textContent =
                    "Password must contain at least one number.";

                return;

            }


            // SPECIAL CHARACTER

            if (!/[^A-Za-z0-9]/.test(newPassword)) {

                message.textContent =
                    "Password must contain at least one special character.";

                return;

            }


            // CONFIRM PASSWORD

            if (
                newPassword !==
                confirmPassword
            ) {

                message.textContent =
                    "Passwords do not match.";

                return;

            }


            if (!resetToken) {

                message.textContent =
                    "Reset session expired. Please try again.";

                return;

            }


            message.textContent =
                "Resetting password...";


            try {

                const response =
                    await fetch(
                        "/api/reset-password",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    resetToken,
                                    newPassword
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "Password reset failed.";

                    return;

                }


                sessionStorage.clear();


                message.textContent =
                    "Password reset successfully. Returning to login...";


                setTimeout(
                    function () {

                        showLogin();

                    },
                    1500
                );


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// REGISTRATION → LOGIN
// =====================================================

document
    .getElementById("backToLogin")
    .addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            showLogin();

        }
    );


// =====================================================
// PASSWORD SHOW / HIDE
// =====================================================

document
    .getElementById("toggleLoginPassword")
    .addEventListener(
        "click",
        function () {

            const password =
                document.getElementById(
                    "loginPassword"
                );


            if (
                password.type === "password"
            ) {

                password.type = "text";

                this.textContent = "Hide";

            } else {

                password.type = "password";

                this.textContent = "Show";

            }

        }
    );


document
    .getElementById("toggleRegisterPassword")
    .addEventListener(
        "click",
        function () {

            const password =
                document.getElementById(
                    "registerPassword"
                );


            if (
                password.type === "password"
            ) {

                password.type = "text";

                this.textContent = "Hide";

            } else {

                password.type = "password";

                this.textContent = "Show";

            }

        }
    );


// =====================================================
// LOGIN
// =====================================================

document
    .getElementById("loginForm")
    .addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();


            const email =
                document
                    .getElementById("loginEmail")
                    .value
                    .trim();


            const password =
                document
                    .getElementById("loginPassword")
                    .value
                    .trim();


            const message =
                document.getElementById(
                    "loginMessage"
                );


            message.textContent = "";


            if (!email || !password) {

                message.textContent =
                    "Please enter your email and password.";

                return;

            }


            message.textContent =
                "Checking your credentials...";


            try {

                const response =
                    await fetch(
                        "/api/login",
                        {
                            method: "POST",

                            credentials: "include",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    email,
                                    password
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "Login failed.";

                    return;

                }


                if (data.mfaRequired) {

                    sessionStorage.setItem(
                        "loginChallengeId",
                        data.challengeId
                    );

                    showLoginOTP();

                }

            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// LOGIN OTP
// =====================================================

document
    .getElementById("verifyLoginOTP")
    .addEventListener(
        "click",
        async function () {

            const otp =
                document
                    .getElementById("loginOTP")
                    .value
                    .trim();


            const challengeId =
                sessionStorage.getItem(
                    "loginChallengeId"
                );


            const error =
                document.getElementById(
                    "loginOTPError"
                );


            const message =
                document.getElementById(
                    "loginOTPMessage"
                );


            error.textContent = "";

            message.textContent = "";


            if (!/^\d{6}$/.test(otp)) {

                error.textContent =
                    "Enter a valid 6-digit OTP.";

                return;

            }


            if (!challengeId) {

                error.textContent =
                    "Login session expired. Please login again.";

                return;

            }


            message.textContent =
                "Verifying OTP...";


            try {

                const response =
                    await fetch(
                        "/api/verify-login-otp",
                        {
                            method: "POST",

                            credentials: "include",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    challengeId,
                                    otp
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "OTP verification failed.";

                    return;

                }


                sessionStorage.removeItem(
                    "loginChallengeId"
                );


                await loadDashboard();


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// LOAD DASHBOARD
// =====================================================

async function loadDashboard() {

    try {

        const response =
            await fetch(
                "/api/me",
                {
                    method: "GET",
                    credentials: "include"
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            showLogin();

            return;

        }


        document.getElementById(
            "dashboardName"
        ).textContent =
            data.user.name;


        document.getElementById(
            "dashboardEmail"
        ).textContent =
            data.user.email;


        document.getElementById(
            "dashboardMFA"
        ).textContent =
            data.user.mfaEnabled
                ? "Enabled"
                : "Disabled";


        showDashboard();


    } catch (error) {

        console.error(error);

        showLogin();

    }

}


// =====================================================
// LOGOUT
// =====================================================

document
    .getElementById("logoutButton")
    .addEventListener(
        "click",
        async function () {

            const message =
                document.getElementById(
                    "dashboardMessage"
                );


            try {

                const response =
                    await fetch(
                        "/api/logout",
                        {
                            method: "POST",
                            credentials: "include"
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "Logout failed.";

                    return;

                }


                sessionStorage.clear();

                showLogin();


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to logout.";

            }

        }
    );


// =====================================================
// REGISTRATION
// =====================================================

document
    .getElementById("registrationForm")
    .addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();


            const name =
                document
                    .getElementById("registerName")
                    .value
                    .trim();


            const email =
                document
                    .getElementById("registerEmail")
                    .value
                    .trim();


            const phone =
                document
                    .getElementById("registerPhone")
                    .value
                    .trim();


            const password =
                document
                    .getElementById("registerPassword")
                    .value
                    .trim();


            const message =
                document.getElementById(
                    "registrationMessage"
                );


            if (
                !name ||
                !email ||
                !phone ||
                !password
            ) {

                message.textContent =
                    "Please fill in all fields.";

                return;

            }


            // PASSWORD STRENGTH

            if (password.length < 8) {

                message.textContent =
                    "Password must be at least 8 characters long.";

                return;

            }


            if (!/[A-Z]/.test(password)) {

                message.textContent =
                    "Password must contain at least one uppercase letter.";

                return;

            }


            if (!/[a-z]/.test(password)) {

                message.textContent =
                    "Password must contain at least one lowercase letter.";

                return;

            }


            if (!/[0-9]/.test(password)) {

                message.textContent =
                    "Password must contain at least one number.";

                return;

            }


            if (!/[^A-Za-z0-9]/.test(password)) {

                message.textContent =
                    "Password must contain at least one special character.";

                return;

            }


            message.textContent =
                "Creating your account...";


            try {

                const response =
                    await fetch(
                        "/api/register",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    name,
                                    email,
                                    phone,
                                    password
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message ||
                        "Registration failed.";

                    return;

                }


                sessionStorage.setItem(
                    "registrationChallengeId",
                    data.challengeId
                );
                sessionStorage.setItem(
    "registrationEmail",
    email
);


                showEmailOTP();


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// EMAIL OTP
// =====================================================

document
    .getElementById("verifyEmailOTP")
    .addEventListener(
        "click",
        async function () {

            const otp =
                document
                    .getElementById("emailOTP")
                    .value
                    .trim();


            const challengeId =
                sessionStorage.getItem(
                    "registrationChallengeId"
                );


            const message =
                document.getElementById(
                    "emailOTPMessage"
                );


            if (!/^\d{6}$/.test(otp)) {

                message.textContent =
                    "Enter a valid 6-digit OTP.";

                return;

            }


            try {

                const response =
                    await fetch(
                        "/api/verify-email-otp",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    challengeId,
                                    otp
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message;

                    return;

                }


                sessionStorage.setItem(
                    "registrationUserId",
                    data.userId
                );


                await sendSMSOTP();


            } catch (error) {

                console.error(error);

                message.textContent =
                    "Unable to connect to the server.";

            }

        }
    );


// =====================================================
// SEND SMS OTP
// =====================================================

async function sendSMSOTP() {

    const userId =
        sessionStorage.getItem(
            "registrationUserId"
        );


    try {

        const response =
            await fetch(
                "/api/send-sms-otp",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body:
                        JSON.stringify({
                            userId
                        })
                }
            );


        const data =
            await response.json();


        if (!response.ok) {

            return;

        }


        sessionStorage.setItem(
            "smsChallengeId",
            data.challengeId
        );


        showSMSOTP();


    } catch (error) {

        console.error(error);

    }

}


// =====================================================
// SMS OTP
// =====================================================

document
    .getElementById("verifySMSOTP")
    .addEventListener(
        "click",
        async function () {

            const otp =
                document
                    .getElementById("smsOTP")
                    .value
                    .trim();


            const challengeId =
                sessionStorage.getItem(
                    "smsChallengeId"
                );


            const message =
                document.getElementById(
                    "smsOTPMessage"
                );


            if (!/^\d{6}$/.test(otp)) {

                message.textContent =
                    "Enter a valid 6-digit OTP.";

                return;

            }


            try {

                const response =
                    await fetch(
                        "/api/verify-sms-otp",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    challengeId,
                                    otp
                                })
                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    message.textContent =
                        data.message;

                    return;

                }


                showSuccess();


            } catch (error) {

                console.error(error);

            }

        }
    );


// =====================================================
// SUCCESS → LOGIN
// =====================================================

document
    .getElementById("goToLogin")
    .addEventListener(
        "click",
        function () {

            sessionStorage.clear();

            showLogin();

        }
    );


// =====================================================
// BACK TO LOGIN FROM LOGIN OTP
// =====================================================

document
    .getElementById("backToLoginFromOTP")
    .addEventListener(
        "click",
        function (event) {

            event.preventDefault();

            sessionStorage.removeItem(
                "loginChallengeId"
            );

            showLogin();

        }
    );
// =====================================================
// OTP RESEND COUNTDOWN
// =====================================================

let emailResendTimer = 0;
let smsResendTimer = 0;

let emailTimerInterval = null;
let smsTimerInterval = null;


// =====================================================
// EMAIL OTP RESEND
// =====================================================

document
    .getElementById("resendEmailOTP")
    .addEventListener(
        "click",
        async function (event) {

            event.preventDefault();

            if (emailResendTimer > 0) {
                return;
            }

            const email =
                sessionStorage.getItem(
                    "registrationEmail"
                );

            const timer =
                document.getElementById(
                    "emailResendTimer"
                );

            if (!email) {

                timer.textContent =
                    "Registration session expired. Please register again.";

                return;

            }

            timer.textContent =
                "Sending new verification code...";

            try {

                const response =
                    await fetch(
                        "/api/resend-email-otp",
                        {

                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({
                                    email
                                })

                        }
                    );


                const data =
                    await response.json();


                if (!response.ok) {

                    timer.textContent =
                        data.message ||
                        "Unable to resend OTP.";

                    return;

                }


                sessionStorage.setItem(
                    "registrationChallengeId",
                    data.challengeId
                );


                timer.textContent =
                    data.message;


                startEmailCountdown();


            } catch (error) {

                console.error(error);

                timer.textContent =
                    "Unable to connect to the server.";

            }

        }
    );
// =====================================================
// EMAIL COUNTDOWN
// =====================================================

function startEmailCountdown() {

    emailResendTimer = 60;

    const timer =
        document.getElementById(
            "emailResendTimer"
        );


    if (emailTimerInterval) {

        clearInterval(
            emailTimerInterval
        );

    }


    emailTimerInterval =
        setInterval(
            function () {

                timer.textContent =
                    `Resend available in ${emailResendTimer}s`;

                emailResendTimer--;


                if (
                    emailResendTimer < 0
                ) {

                    clearInterval(
                        emailTimerInterval
                    );

                    timer.textContent =
                        "You can request another code.";

                }

            },
            1000
        );

}


// =====================================================
// SMS COUNTDOWN
// =====================================================

function startSMSCountdown() {

    smsResendTimer = 60;

    const timer =
        document.getElementById(
            "smsResendTimer"
        );


    if (smsTimerInterval) {

        clearInterval(
            smsTimerInterval
        );

    }


    smsTimerInterval =
        setInterval(
            function () {

                timer.textContent =
                    `Resend available in ${smsResendTimer}s`;

                smsResendTimer--;


                if (
                    smsResendTimer < 0
                ) {

                    clearInterval(
                        smsTimerInterval
                    );

                    timer.textContent =
                        "You can request another code.";

                }

            },
            1000
        );

}