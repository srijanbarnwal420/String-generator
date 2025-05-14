// Required dependencies
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const uuid = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize database
const db = new sqlite3.Database('./auth.db', (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Connected to the SQLite database');
    initializeDatabase();
  }
});

// Create tables if they don't exist
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        failed_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP
      )
    `);

    // Login attempts tracking
    db.run(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        username TEXT,
        success BOOLEAN
      )
    `);

    console.log('Database tables initialized');
  });
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Security headers with Helmet
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
    },
  },
  xFrameOptions: { action: 'deny' }, // Prevent clickjacking
  hsts: { maxAge: 15552000, includeSubDomains: true } // HSTS for 6 months
}));

// Session configuration with secure cookies
app.use(session({
  genid: () => uuid.v4(),
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }),
  secret: process.env.SESSION_SECRET || 'use-a-strong-random-secret-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Prevents client-side JS from reading the cookie
    secure: process.env.NODE_ENV === 'production', // Requires HTTPS in production
    sameSite: 'strict', // Prevents CSRF attacks
    maxAge: 1000 * 60 * 60 * 2 // 2 hours
  }
}));

// CSRF protection
const csrfProtection = csrf({ cookie: { httpOnly: true, sameSite: 'strict' } });
app.use(csrfProtection);

// Rate limiting for login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per windowMs per IP
  message: { error: 'Too many login attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Input validation middleware for registration
const validateRegistration = [
  body('username')
    .trim()
    .isLength({ min: 4, max: 30 })
    .withMessage('Username must be between 4 and 30 characters')
    .isAlphanumeric()
    .withMessage('Username can only contain letters and numbers'),
  body('email')
    .trim()
    .isEmail()
    .withMessage('Must provide a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 10 })
    .withMessage('Password must be at least 10 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

// Input validation middleware for login
const validateLogin = [
  body('username').trim().notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required')
];

// Function to log login attempts
function logLoginAttempt(ip, username, success) {
  const stmt = db.prepare(`
    INSERT INTO login_attempts (ip_address, username, success)
    VALUES (?, ?, ?)
  `);
  stmt.run(ip, username, success ? 1 : 0);
  stmt.finalize();
}

// Function to check if account is locked
function isAccountLocked(username) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT locked_until FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) return reject(err);
        
        if (!row || !row.locked_until) return resolve(false);
        
        const lockedUntil = new Date(row.locked_until);
        const now = new Date();
        
        if (lockedUntil > now) {
          // Account is locked
          return resolve(true);
        } else {
          // Lock period has expired, reset the lock
          db.run(
            'UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE username = ?',
            [username],
            (err) => {
              if (err) return reject(err);
              resolve(false);
            }
          );
        }
      }
    );
  });
}

// Function to increment failed attempts and lock account if needed
function handleFailedLogin(username) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT failed_attempts FROM users WHERE username = ?',
      [username],
      (err, row) => {
        if (err) return reject(err);
        if (!row) return resolve(); // User not found
        
        const failedAttempts = (row.failed_attempts || 0) + 1;
        let lockedUntil = null;
        
        // Lock account after 5 failed attempts for 30 minutes
        if (failedAttempts >= 5) {
          const lockTime = new Date();
          lockTime.setMinutes(lockTime.getMinutes() + 30);
          lockedUntil = lockTime.toISOString();
        }
        
        db.run(
          'UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?',
          [failedAttempts, lockedUntil, username],
          (err) => {
            if (err) return reject(err);
            resolve();
          }
        );
      }
    );
  });
}

// Function to reset failed attempts on successful login
function resetFailedAttempts(username) {
  return new Promise((resolve, reject) => {
    db.run(
      'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP WHERE username = ?',
      [username],
      (err) => {
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, 'public')));

// Route for the home page
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// Routes
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Registration endpoint
app.post('/api/register', validateRegistration, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password } = req.body;
    
    // Generate a unique user ID
    const userId = uuid.v4();
    
    // Generate a salt and hash the password (cost factor of 12 is recommended for bcrypt)
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Insert the new user
    db.run(
      'INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)',
      [userId, username, email, hashedPassword],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(409).json({ error: 'Username or email already exists' });
          }
          console.error('Registration error:', err);
          return res.status(500).json({ error: 'An error occurred during registration' });
        }
        
        // Successful registration
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});

// Login endpoint
app.post('/api/login', loginLimiter, validateLogin, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const ip = req.ip;

    // Check if account is locked
    const locked = await isAccountLocked(username);
    if (locked) {
      logLoginAttempt(ip, username, false);
      return res.status(403).json({ error: 'Account is temporarily locked due to too many failed attempts' });
    }
    
    // Query the database for the user
    db.get(
      'SELECT * FROM users WHERE username = ?',
      [username],
      async (err, user) => {
        if (err) {
          console.error('Login query error:', err);
          return res.status(500).json({ error: 'An error occurred during login' });
        }
        
        // User not found or password doesn't match
        if (!user || !(await bcrypt.compare(password, user.password))) {
          // Log the failed attempt
          logLoginAttempt(ip, username, false);
          
          // Increment failed attempts and potentially lock the account
          if (user) {
            await handleFailedLogin(username);
          }
          
          // Use a vague error message to prevent username enumeration
          return res.status(401).json({ error: 'Invalid username or password' });
        }
        
        // Log successful login
        logLoginAttempt(ip, username, true);
        
        // Reset failed attempts
        await resetFailedAttempts(username);
        
        // Create a user object to store in session
        const userData = {
          id: user.id,
          username: user.username,
          email: user.email
        };
        
        // Store user data temporarily
        const tempUserData = userData;
        
        // Regenerate session ID to prevent session fixation
        req.session.regenerate((err) => {
          if (err) {
            console.error('Session regeneration error:', err);
            return res.status(500).json({ error: 'An error occurred during login' });
          }
          
          // Restore user data to the new session
          req.session.user = tempUserData;
          
          // Save the session to ensure it's stored before sending response
          req.session.save((err) => {
            if (err) {
              console.error('Session save error:', err);
              return res.status(500).json({ error: 'An error occurred during login' });
            }
            
            console.log('User logged in successfully, session saved with user:', req.session.user);
            res.json({ message: 'Login successful', user: { username: user.username, email: user.email } });
          });
        });
      }
    );
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'An error occurred during login' });
  }
});

// Create a deliberately vulnerable endpoint (for demonstration purposes only)
// This endpoint doesn't use CSRF protection
app.post('/api/vulnerable/update-email', async (req, res) => {
  // This endpoint intentionally skips CSRF check to demonstrate vulnerability
  try {
    // Only process if user is logged in
    if (!req.session.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { newEmail } = req.body;
    const userId = req.session.user.id;
    
    console.log(`VULNERABLE ENDPOINT: Attempting to update email to ${newEmail} for user ${userId}`);
    
    // Update the email
    db.run(
      'UPDATE users SET email = ? WHERE id = ?',
      [newEmail, userId],
      function(err) {
        if (err) {
          console.error('Email update error:', err);
          return res.status(500).json({ error: 'An error occurred while updating the email' });
        }

        // Update session info
        req.session.user.email = newEmail;
        
        res.json({ 
          message: 'Email updated successfully', 
          warning: 'This endpoint is intentionally vulnerable to CSRF attacks'
        });
      }
    );
  } catch (error) {
    console.error('Email update error:', error);
    res.status(500).json({ error: 'An error occurred while updating the email' });
  }
});

// Logout endpoint
app.post('/api/logout', csrfProtection, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ error: 'An error occurred during logout' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logged out successfully' });
  });
});

// Protected route example
app.get('/api/profile', (req, res) => {
  console.log('Profile request received, session:', req.session.id);
  console.log('User in session:', req.session.user);
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  res.json({ user: req.session.user });
});

// Password change endpoint
app.post('/api/change-password', csrfProtection, [
  body('currentPassword').notEmpty().withMessage('Current password is required'),
  body('newPassword')
    .isLength({ min: 10 })
    .withMessage('Password must be at least 10 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
], async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    if (!req.session.user) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    const { currentPassword, newPassword } = req.body;
    const userId = req.session.user.id;

    // Get the current user
    db.get(
      'SELECT password FROM users WHERE id = ?',
      [userId],
      async (err, user) => {
        if (err) {
          console.error('Password change error:', err);
          return res.status(500).json({ error: 'An error occurred while changing the password' });
        }

        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
          return res.status(401).json({ error: 'Current password is incorrect' });
        }

        // Generate new password hash
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the password
        db.run(
          'UPDATE users SET password = ? WHERE id = ?',
          [hashedPassword, userId],
          function(err) {
            if (err) {
              console.error('Password update error:', err);
              return res.status(500).json({ error: 'An error occurred while updating the password' });
            }

            res.json({ message: 'Password updated successfully' });
          }
        );
      }
    );
  } catch (error) {
    console.error('Password change error:', error);
    res.status(500).json({ error: 'An error occurred while changing the password' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ error: 'CSRF token validation failed' });
  }
  
  console.error('Server error:', err);
  res.status(500).json({ error: 'An internal server error occurred' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Clean up database connection on exit
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) {
      return console.error(err.message);
    }
    console.log('Database connection closed');
    process.exit(0);
  });
});

// Export for testing
module.exports = app;
