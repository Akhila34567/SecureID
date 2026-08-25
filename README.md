# SecureID

SecureID is a secure user authentication and identity management web application built with Node.js, Express.js, SQLite, and a simple HTML/CSS/JavaScript frontend.

The application provides multi-factor authentication, OTP verification, password reset, account lockout, session-based authentication, and security validation.

---

## Features

### User Registration

- User registration with name, email, mobile number, and password
- Email verification using OTP
- SMS verification using OTP
- Multi-factor authentication (MFA)
- Duplicate email protection

### Login

- Email and password authentication
- Login OTP verification
- Server-side session authentication
- Authenticated dashboard
- Secure logout

### Password Security

- Passwords are hashed using bcrypt
- Minimum password length of 8 characters
- Requires uppercase letter
- Requires lowercase letter
- Requires number
- Requires special character

### Forgot Password

- Password reset request
- Password reset OTP
- OTP verification
- Secure password update

### OTP Security

- Six-digit OTPs
- OTPs are stored as SHA-256 hashes
- OTP expiration
- Maximum OTP attempts
- OTP resend cooldown
- OTP verification for registration, login, and password reset

### Account Security

- Failed login attempt tracking
- Temporary account lockout
- Security headers using Helmet
- Input validation
- Email validation
- Mobile number validation
- Session protection

### Database

- SQLite database
- Persistent user storage
- User data remains available after server restart

---

## Technologies Used

### Frontend

- HTML5
- CSS3
- JavaScript

### Backend

- Node.js
- Express.js

### Security

- bcryptjs
- JSON Web Token support
- Express Session
- Helmet
- OTP hashing
- Account lockout

### Database

- SQLite
- better-sqlite3

### Other

- CORS
- dotenv

---

## Project Structure

```text
SecureID/
│
├── public/
│   ├── index.html
│   ├── script.js
│   └── style.css
│
├── server/
│   ├── database.js
│   └── server.js
│
├── .gitignore
├── package.json
├── package-lock.json
└── README.md