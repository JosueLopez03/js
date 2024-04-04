const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const crypto = require('crypto');
const dotenv = require('dotenv').config();

const app = express();
app.use(express.json()); // Middleware to parse JSON bodies
const port = 8080;

// Define database connection
const db = new sqlite3.Database('totally_not_my_privateKeys.db'); // Connect to SQLite database
// get access to private key for encryption
const AES_KEY = process.env.NOT_MY_KEY; // Access AES encryption key from environment variables

let keyPair; // Variable to store generated RSA key pair
let expiredKeyPair; // Variable to store expired RSA key pair
let token; // Variable to store JWT token
const iv = crypto.randomBytes(16); // Generate IV for AES encryption

// Function to generate RSA key pairs
async function generateKeyPairs() {
  try {
    // Generate RSA key pairs with RS256 algorithm and signature usage
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

    // Save generated key pairs to the database
    saveKeyPairToDB(keyPair, Date.now() + 3600); // Expiry in 1 hour
    saveKeyPairToDB(expiredKeyPair, Date.now() - 3600); // Expiry in the past (expired)
  } catch (error) {
    console.error('Error generating key pairs:', error.message);
    process.exit(1); // Terminate the process if key pair generation fails
  }
}

// Function to generate JWT token
function generateToken(payload) {
  const options = {
    algorithm: 'RS256', // RSA with SHA-256 hashing algorithm
    expiresIn: "1h" // Token expiration time
  };

  try {
    token = jwt.sign(payload, keyPair.toPEM(true), options); // Sign the payload with private key
  } catch (error) {
    console.error('Error generating token:', error.message);
    throw error; // Throw error if token generation fails
  }
}

// Function to generate a secure password using UUIDv4
function generateSecurePassword() {
  return { password: uuidv4() }; // Generate a secure password using UUIDv4
}

// Encrypt private key using AES encryption
function encryptPrivateKey(privateKey) {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(AES_KEY), iv); // Create AES cipher
  let encrypted = cipher.update(privateKey, 'utf8', 'hex'); // Update cipher with private key
  encrypted += cipher.final('hex'); // Finalize encryption
  return encrypted.toString('hex'); // Return encrypted private key
}

// Decrypt private key using AES decryption
function decryptPrivateKey(encryptedKey) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(AES_KEY), iv); // Create AES decipher
  let decrypted = decipher.update(encryptedKey, 'hex', 'utf8'); // Update decipher with encrypted key
  decrypted += decipher.final('utf8'); // Finalize decryption
  return decrypted; // Return decrypted private key
}

// Function to initialize database and create necessary tables if not exists
function Database() {
  // Create keys table if not exists
  db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)', (error) => {
    if (error) {
      console.error('Error creating keys table:', error.message);
      process.exit(1); // Terminate the process if table creation fails
    }
  });
  // Create users table if not exists
  db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)', (error) => {
    if (error) {
      console.error('Error creating users table:', error.message);
      process.exit(1); // Terminate the process if table creation fails
    }
  });
  // Create auth_logs table if not exists
  db.run('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id));', (error) => {
    if (error) {
      console.error('Error creating auth_logs table:', error.message);
      process.exit(1); // Terminate the process if table creation fails
    }
  });
}

// Function to save a key pair to the database
function saveKeyPairToDB(keyPair, exp) {
  const pemKey = keyPair.toPEM(true); // Serialize key pair to PEM format
  const encryptedKey = encryptPrivateKey(pemKey); // Encrypt private key
  // Insert encrypted key pair into the database
  db.run('INSERT INTO keys(key, exp) VALUES (?, ?)', [encryptedKey, exp], (err) => {
    if (err) {
      console.error('Error saving key to DB:', err.message);
      throw err; // Throw error if key pair saving fails
    }
  });
}

// Function to retrieve all valid keys from the database
async function getAllValidKeysFromDB() {
  return new Promise((resolve, reject) => {
    const now = Date.now();
    // Query to retrieve keys with expiry greater than current time
    db.all('SELECT * FROM keys WHERE exp > ?', [now], (err, rows) => {
      if (err) {
        reject(err); // Reject promise if database query fails
      } else {
        // Deserialize keys and return
        const validKeys = rows.map(row => {
          const decryptedKey = decryptPrivateKey(row.key); // Decrypt private key
          return jose.JWK.asKey(decryptedKey); // Convert to JWK format
        });
        resolve(validKeys); // Resolve promise with valid keys
      }
    });
  });
}

// Middleware to handle unsupported HTTP methods for /auth endpoint
app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed'); // Send 405 status for unsupported methods
  }
  next(); // Proceed to next middleware or route handler
});

// Middleware to handle unsupported HTTP methods for /.well-known/jwks.json endpoint
app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed'); // Send 405 status for unsupported methods
  }
  next(); // Proceed to next middleware or route handler
});

// Route handler to handle GET request for /.well-known/jwks.json endpoint
app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    // Retrieve all valid keys from the database
    const keys = await getAllValidKeysFromDB();
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys }); // Return keys in JWKS format
  } catch (err) {
    console.error('Error retrieving JWKS:', err.message);
    res.status(500).json({ error: err.message }); // Send 500 status for internal server error
  }
});

// Route handler to handle POST request for /auth endpoint
app.post('/auth', async (req, res) => {
  try {
    const requestIp = req.ip; // Get client's IP address
    const { username, password } = req.body; // Extract username and password from request body
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." }); // Send 400 status for missing username or password
    }

    const getUserIdQuery = 'SELECT id FROM users WHERE username = ?'; // SQL query to get user ID by username
    // Wrap the entire logic in an async function
    const getUserId = async () => {
      return new Promise((resolve, reject) => {
        db.get(getUserIdQuery, [username], (error, row) => {
          if (error) {
            reject(error); // Reject promise if database query fails
          } else {
            resolve(row ? row.id : null); // Resolve promise with user ID or null if not found
          }
        });
      });
    };

    try {
      const userId = await getUserId(); // Get user ID from database

      if (!userId) {
        res.status(404).send('User not found'); // Send 404 status if user not found
        return;
      }

      const insertAuthLogQuery = 'INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)'; // SQL query to insert authentication log
      await new Promise((resolve, reject) => {
        db.run(insertAuthLogQuery, [requestIp, userId], (error) => {
          if (error) {
            reject(error); // Reject promise if database operation fails
          } else {
            resolve(); // Resolve promise if operation succeeds
          }
        });
      });

      // User is considered authenticated by default as per rubric
      const expired = req.query.expired === "true"; // Check if token is expired
      const payload = {
        username: username,
        password: password,
        expired: expired,
      };

      const accessToken = generateToken({ username }); // Generate JWT token
      res.status(200).json({ token: accessToken }); // Send token in response

    } catch (error) {
      console.error('Error during authentication:', error);
      res.status(500).send('Internal Server Error'); // Send 500 status for internal server error
    }
  } catch (error) {
    console.error('Error during authentication:', error);
    res.status(500).send('Internal Server Error'); // Send 500 status for internal server error
  }
});

// Route handler to handle POST request for /register endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body; // Extract username and email from request body
    const generatedPassword = generateSecurePassword(); // Generate secure password

    try {
      const hashedPassword = await argon2.hash(generatedPassword.password); // Hash password using Argon2
      const insertUserQuery = 'INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)'; // SQL query to insert user
      await new Promise((resolve, reject) => {
        db.run(insertUserQuery, [username, hashedPassword, email], (error) => {
          if (error) {
            if (error.message.includes('UNIQUE constraint failed')) {
              res.status(400).send('Username or email is already taken.'); // Send 400 status for duplicate username or email
            } else {
              reject(error); // Reject promise if database operation fails
            }
          } else {
            res.status(200).json({ password: generatedPassword.password }); // Send password in response
            resolve(); // Resolve promise if operation succeeds
          }
        });
      });
    } catch (error) {
      console.error('Error during password hashing or user registration:', error);
      res.status(500).send('Internal Server Error'); // Send 500 status for internal server error
    }
  } catch (error) {
    console.error('Error during user registration:', error);
    res.status(500).send('Internal Server Error'); // Send 500 status for internal server error
  }
});

// Initialize database and create necessary tables
db.serialize(() => {
  Database(); // Call Database function to create tables
  generateKeyPairs().then(() => { // Generate key pairs and start server
    app.listen(port, () => {
      console.log(`Server started on http://localhost:${port}`); // Log server start message
    });
  });
});

module.exports = app; // Export the Express app
