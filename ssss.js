// ============================================================================
// DELIBERATELY VULNERABLE Express.js API - FOR DAST SCANNER TESTING ONLY
// ============================================================================
// Vulnerabilities present:
//   1. Mass Assignment (register + update profile)
//   2. IDOR (password update, profile view, delete)
//   3. Weak JWT (none algorithm, weak secret, no expiry validation)
//   4. ReDoS (email, username, URL validators)
//   5. Bonus: User/Password Enumeration, No Rate Limiting, Debug endpoint
// ============================================================================

const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// ============================================================================
// "DATABASE" - In-memory store
// ============================================================================
const users = [
  {
    id: 1,
    username: 'admin',
    password: 'admin123',          // Plaintext passwords (vuln)
    email: 'admin@company.com',
    role: 'admin',
    isAdmin: true,
    internalNotes: 'Super admin - has access to billing',
    apiKey: 'sk-prod-9a8b7c6d5e4f3g2h1i',
    salary: 150000,
    ssn: '123-45-6789',
    department: 'Engineering',
    resetToken: null,
  },
  {
    id: 2,
    username: 'john',
    password: 'john2024',
    email: 'john@company.com',
    role: 'user',
    isAdmin: false,
    internalNotes: 'Regular employee',
    apiKey: 'sk-prod-1a2b3c4d5e6f7g8h9i',
    salary: 75000,
    ssn: '987-65-4321',
    department: 'Marketing',
    resetToken: null,
  },
];

let nextId = 3;

// ============================================================================
// VULNERABILITY #3: Weak JWT Configuration
// ============================================================================
// Problem 1: Trivially guessable secret
const JWT_SECRET = 'secret';

// Problem 2: Signs with HS256 but accepts ANY algorithm on decode (including "none")
function signToken(payload) {
  // No expiry set - tokens live forever
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256' });
}

// Problem 3: Decodes WITHOUT verifying algorithm - allows "none" algorithm attack
// An attacker can craft a token with alg:"none" and no signature
function decodeToken(token) {
  try {
    // VULNERABLE: algorithms not restricted on verify
    // Attacker can use alg:"none" to forge tokens without the secret
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
    return decoded;
  } catch (err) {
    // VULNERABLE: Falls back to unverified decode if verify fails
    // This means ANY token content is trusted
    try {
      return jwt.decode(token, { complete: false });
    } catch {
      return null;
    }
  }
}

// Problem 4: Weak token extraction - no Bearer scheme validation
function extractToken(req) {
  const authHeader = req.headers['authorization'] || req.headers['x-auth-token'] || '';
  // Accepts token from query param too (leaks in logs, referer, browser history)
  const queryToken = req.query.token;

  if (queryToken) return queryToken;
  if (authHeader.includes(' ')) return authHeader.split(' ')[1];
  return authHeader; // Accepts raw token without Bearer prefix
}

// ============================================================================
// AUTH MIDDLEWARE - Broken on purpose
// ============================================================================
function authMiddleware(req, res, next) {
  const token = extractToken(req);
  if (!token) {
    return res.status(401).json({ status: 'fail', message: 'No token provided' });
  }

  const decoded = decodeToken(token);
  if (!decoded) {
    return res.status(401).json({ status: 'fail', message: 'Invalid token' });
  }

  // VULNERABLE: Trusts whatever is in the token without DB lookup
  // If attacker forges token with {sub: "admin", role: "admin"}, they're admin
  req.user = decoded;
  next();
}

// Optional auth - doesn't fail if no token, just sets req.user
function optionalAuth(req, res, next) {
  const token = extractToken(req);
  if (token) {
    req.user = decodeToken(token);
  }
  next();
}

// ============================================================================
// VULNERABILITY #4: ReDoS Patterns
// ============================================================================

// ReDoS #1: Email regex with catastrophic backtracking
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential time
const EMAIL_REGEX = /^([0-9a-zA-Z]([-.\w]*[0-9a-zA-Z])*@{1}([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,9})$/;

// ReDoS #2: Username regex with nested quantifiers
// Input: "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" causes catastrophic backtracking
const USERNAME_REGEX = /^([a-zA-Z0-9]+[-._]?)*[a-zA-Z0-9]+$/;

// ReDoS #3: URL validation regex
// Input: "http://aaaaaaaaaaaaaaaaaaaaaaaa!" causes exponential time
const URL_REGEX = /^(https?:\/\/)?([\w.-]+)(\.[\w.-]+)*(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)*$/;

function validateEmail(email) {
  return EMAIL_REGEX.test(email);
}

function validateUsername(username) {
  return USERNAME_REGEX.test(username);
}

function validateUrl(url) {
  return URL_REGEX.test(url);
}

// ============================================================================
// ROUTES
// ============================================================================

// ----------- PUBLIC ROUTES -----------

// GET /api/users - No auth required (information disclosure)
app.get('/api/users', (req, res) => {
  // VULNERABLE: Exposes all users without authentication
  // Returns more data than necessary
  const userList = users.map(u => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    department: u.department,
  }));
  res.json({ status: 'success', users: userList });
});

// GET /api/debug/users - Debug endpoint with FULL user data (no auth!)
app.get('/api/debug/users', (req, res) => {
  // VULNERABLE: Exposes passwords, SSNs, API keys, everything
  res.json({ status: 'success', users: users });
});

// ----------- VULNERABILITY #1: Mass Assignment on Register -----------

// POST /api/register
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ status: 'fail', message: 'Missing required fields' });
  }

  // ReDoS: Validate email with vulnerable regex
  if (!validateEmail(email)) {
    return res.status(400).json({ status: 'fail', message: 'Invalid email format' });
  }

  // ReDoS: Validate username with vulnerable regex
  if (!validateUsername(username)) {
    return res.status(400).json({ status: 'fail', message: 'Invalid username format' });
  }

  if (users.find(u => u.username === username)) {
    // VULNERABLE: User enumeration - confirms username exists
    return res.status(409).json({ status: 'fail', message: 'Username already taken' });
  }

  // =========================================================================
  // MASS ASSIGNMENT VULNERABILITY
  // =========================================================================
  // Spreads ALL request body fields directly into the user object
  // Attacker can send: { "username": "hacker", "password": "pass",
  //   "email": "h@h.com", "role": "admin", "isAdmin": true, "salary": 999999 }
  // and ALL those fields get stored
  const newUser = {
    id: nextId++,
    role: 'user',          // Default role...
    isAdmin: false,         // Default admin flag...
    internalNotes: '',
    apiKey: `sk-dev-${crypto.randomBytes(10).toString('hex')}`,
    salary: 0,
    ssn: '',
    department: 'Unassigned',
    resetToken: null,
    ...req.body,            // <-- MASS ASSIGNMENT: Overwrites ALL defaults above
    password: password,     // Still store plaintext (vuln)
  };

  users.push(newUser);

  // VULNERABLE: Weak JWT - no expiry, trivial secret
  const token = signToken({
    sub: newUser.username,
    role: newUser.role,
    isAdmin: newUser.isAdmin,
    id: newUser.id,
  });

  res.status(201).json({
    status: 'success',
    message: 'Registration successful',
    auth_token: token,
    user: {
      id: newUser.id,
      username: newUser.username,
      email: newUser.email,
      role: newUser.role,       // Reflects back the injected role
      isAdmin: newUser.isAdmin, // Reflects back the injected admin flag
    },
  });
});

// POST /api/login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ status: 'fail', message: 'Missing credentials' });
  }

  const user = users.find(u => u.username === username);

  // VULNERABLE: User/Password enumeration - different messages
  if (!user) {
    return res.status(401).json({ status: 'fail', message: 'Username does not exist' });
  }

  // VULNERABLE: Plaintext password comparison
  if (user.password !== password) {
    return res.status(401).json({ status: 'fail', message: 'Password is incorrect' });
  }

  // VULNERABLE: No rate limiting, no account lockout, no MFA

  const token = signToken({
    sub: user.username,
    role: user.role,
    isAdmin: user.isAdmin,
    id: user.id,
  });

  res.json({
    status: 'success',
    message: 'Login successful',
    auth_token: token,
  });
});

// ----------- AUTHENTICATED ROUTES -----------

// GET /api/me - Current user profile
app.get('/api/me', authMiddleware, (req, res) => {
  const user = users.find(u => u.username === req.user.sub);
  if (!user) {
    return res.status(404).json({ status: 'fail', message: 'User not found' });
  }
  res.json({
    status: 'success',
    data: { username: user.username, email: user.email, role: user.role },
  });
});

// ----------- VULNERABILITY #2: IDOR on Profile View -----------

// GET /api/users/:id/profile
app.get('/api/users/:id/profile', authMiddleware, (req, res) => {
  // VULNERABLE: No check that req.user.id === req.params.id
  // Any authenticated user can view ANY user's full profile including SSN, salary, apiKey
  const targetUser = users.find(u => u.id === parseInt(req.params.id));

  if (!targetUser) {
    return res.status(404).json({ status: 'fail', message: 'User not found' });
  }

  // VULNERABLE: Returns sensitive fields to any authenticated user
  res.json({
    status: 'success',
    data: {
      id: targetUser.id,
      username: targetUser.username,
      email: targetUser.email,
      role: targetUser.role,
      department: targetUser.department,
      salary: targetUser.salary,         // Sensitive!
      ssn: targetUser.ssn,               // PII!
      apiKey: targetUser.apiKey,          // Secret!
      internalNotes: targetUser.internalNotes, // Internal!
    },
  });
});

// ----------- VULNERABILITY #2: IDOR on Password Update -----------

// PUT /api/users/:id/password
app.put('/api/users/:id/password', authMiddleware, (req, res) => {
  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ status: 'fail', message: 'Password is required' });
  }

  // VULNERABLE: Uses :id from URL, NOT from JWT token
  // Authenticated user can change ANY user's password
  const targetUser = users.find(u => u.id === parseInt(req.params.id));
  if (!targetUser) {
    return res.status(404).json({ status: 'fail', message: 'User not found' });
  }

  // No old password verification required!
  // No password complexity check!
  targetUser.password = password; // Still plaintext

  res.json({ status: 'success', message: 'Password updated' });
});

// ----------- VULNERABILITY #1+2: Mass Assignment on Profile Update -----------

// PUT /api/users/:id/profile
app.put('/api/users/:id/profile', authMiddleware, (req, res) => {
  // VULNERABLE IDOR: Uses :id from URL instead of JWT
  const targetUser = users.find(u => u.id === parseInt(req.params.id));
  if (!targetUser) {
    return res.status(404).json({ status: 'fail', message: 'User not found' });
  }

  // ReDoS: If email is provided, validate with vulnerable regex
  if (req.body.email && !validateEmail(req.body.email)) {
    return res.status(400).json({ status: 'fail', message: 'Invalid email format' });
  }

  // ReDoS: If website URL is provided, validate with vulnerable regex
  if (req.body.website && !validateUrl(req.body.website)) {
    return res.status(400).json({ status: 'fail', message: 'Invalid URL format' });
  }

  // =========================================================================
  // MASS ASSIGNMENT VULNERABILITY (again, on update)
  // =========================================================================
  // Attacker can PUT: { "role": "admin", "isAdmin": true, "salary": 999999 }
  // to ANY user's profile
  Object.assign(targetUser, req.body);

  res.json({
    status: 'success',
    message: 'Profile updated',
    data: {
      id: targetUser.id,
      username: targetUser.username,
      email: targetUser.email,
      role: targetUser.role,
      isAdmin: targetUser.isAdmin,
    },
  });
});

// ----------- VULNERABILITY #2: IDOR on Delete -----------

// DELETE /api/users/:id
app.delete('/api/users/:id', authMiddleware, (req, res) => {
  // "Admin check" but based on JWT claims which can be forged (vuln #3)
  if (!req.user.isAdmin) {
    return res.status(403).json({ status: 'fail', message: 'Admin access required' });
  }

  // VULNERABLE: Admin check is based on forged JWT, and uses URL param
  const targetIndex = users.findIndex(u => u.id === parseInt(req.params.id));
  if (targetIndex === -1) {
    return res.status(404).json({ status: 'fail', message: 'User not found' });
  }

  users.splice(targetIndex, 1);
  res.json({ status: 'success', message: 'User deleted' });
});

// ----------- ReDoS TRIGGER ENDPOINTS -----------

// POST /api/validate/email - Explicit ReDoS trigger
app.post('/api/validate/email', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ status: 'fail', message: 'Email required' });
  }

  // VULNERABLE: ReDoS - send "aaaaaaaaaaaaaaaaaaaaaaaaaaa!" to hang server
  const start = Date.now();
  const isValid = validateEmail(email);
  const elapsed = Date.now() - start;

  res.json({ valid: isValid, processingTimeMs: elapsed });
});

// POST /api/validate/url - Explicit ReDoS trigger
app.post('/api/validate/url', (req, res) => {
  const { url } = req.body;
  if (!url) {
    return res.status(400).json({ status: 'fail', message: 'URL required' });
  }

  // VULNERABLE: ReDoS - send crafted URL to hang server
  const start = Date.now();
  const isValid = validateUrl(url);
  const elapsed = Date.now() - start;

  res.json({ valid: isValid, processingTimeMs: elapsed });
});

// ----------- BONUS: Password Reset with Weak Token -----------

// POST /api/forgot-password
app.post('/api/forgot-password', (req, res) => {
  const { username } = req.body;
  const user = users.find(u => u.username === username);

  // VULNERABLE: User enumeration
  if (!user) {
    return res.status(404).json({ status: 'fail', message: 'Username not found' });
  }

  // VULNERABLE: Predictable reset token (timestamp-based)
  const resetToken = crypto.createHash('md5')
    .update(user.username + Date.now().toString())
    .digest('hex')
    .substring(0, 8); // Only 8 hex chars = 4 bytes = brute-forceable

  user.resetToken = resetToken;

  // VULNERABLE: Token returned directly in response (should be sent via email)
  res.json({
    status: 'success',
    message: 'Password reset token generated',
    resetToken: resetToken,   // Should never be in response
  });
});

// POST /api/reset-password
app.post('/api/reset-password', (req, res) => {
  const { username, resetToken, newPassword } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || user.resetToken !== resetToken) {
    return res.status(400).json({ status: 'fail', message: 'Invalid reset token' });
  }

  // VULNERABLE: No token expiry check, no password complexity, plaintext storage
  user.password = newPassword;
  user.resetToken = null;

  res.json({ status: 'success', message: 'Password has been reset' });
});

// ----------- SWAGGER / OPENAPI (for your API scanner to consume) -----------

app.get('/api/docs', (req, res) => {
  res.json({
    openapi: '3.0.0',
    info: { title: 'Vulnerable API', version: '1.0.0' },
    paths: {
      '/api/register': {
        post: {
          summary: 'Register new user',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'password', 'email'],
                  properties: {
                    username: { type: 'string' },
                    password: { type: 'string' },
                    email: { type: 'string', format: 'email' },
                  },
                },
              },
            },
          },
        },
      },
      '/api/login': {
        post: {
          summary: 'Login',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'password'],
                  properties: {
                    username: { type: 'string' },
                    password: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
      '/api/users': {
        get: { summary: 'List all users' },
      },
      '/api/users/{id}/profile': {
        get: {
          summary: 'Get user profile',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        },
        put: {
          summary: 'Update user profile',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    email: { type: 'string', format: 'email' },
                    department: { type: 'string' },
                    website: { type: 'string', format: 'uri' },
                  },
                },
              },
            },
          },
        },
      },
      '/api/users/{id}/password': {
        put: {
          summary: 'Change user password',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['password'],
                  properties: {
                    password: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
      '/api/users/{id}': {
        delete: {
          summary: 'Delete user (admin only)',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
        },
      },
      '/api/me': {
        get: { summary: 'Get current user info' },
      },
      '/api/validate/email': {
        post: {
          summary: 'Validate email format',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['email'],
                  properties: { email: { type: 'string' } },
                },
              },
            },
          },
        },
      },
      '/api/validate/url': {
        post: {
          summary: 'Validate URL format',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['url'],
                  properties: { url: { type: 'string' } },
                },
              },
            },
          },
        },
      },
      '/api/forgot-password': {
        post: {
          summary: 'Request password reset',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username'],
                  properties: { username: { type: 'string' } },
                },
              },
            },
          },
        },
      },
      '/api/reset-password': {
        post: {
          summary: 'Reset password with token',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'resetToken', 'newPassword'],
                  properties: {
                    username: { type: 'string' },
                    resetToken: { type: 'string' },
                    newPassword: { type: 'string' },
                  },
                },
              },
            },
          },
        },
      },
      '/api/debug/users': {
        get: { summary: 'Debug - all user data' },
      },
    },
  });
});

// ============================================================================
// START SERVER
// ============================================================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Vulnerable API running on port ${PORT}`);
  console.log(`OpenAPI docs: http://localhost:${PORT}/api/docs`);
  console.log('');
  console.log('=== VULNERABILITIES ACTIVE ===');
  console.log('1. Mass Assignment:  POST /api/register  (send role/isAdmin in body)');
  console.log('2. Mass Assignment:  PUT  /api/users/:id/profile  (Object.assign from body)');
  console.log('3. IDOR:             GET  /api/users/:id/profile  (view any user SSN/salary)');
  console.log('4. IDOR:             PUT  /api/users/:id/password (change any user password)');
  console.log('5. IDOR:             DELETE /api/users/:id        (delete any user)');
  console.log('6. Weak JWT:         alg:none accepted, secret="secret", no expiry');
  console.log('7. ReDoS:            POST /api/validate/email     (send "aaa...aaa!")');
  console.log('8. ReDoS:            POST /api/validate/url       (send crafted URL)');
  console.log('9. ReDoS:            POST /api/register + PUT profile (email/username regex)');
  console.log('10. User Enum:       POST /api/login              (different error messages)');
  console.log('11. Debug Endpoint:  GET  /api/debug/users        (exposes everything, no auth)');
  console.log('12. Weak Reset:      POST /api/forgot-password    (predictable token in response)');
  console.log('==============================');
});

module.exports = app;
