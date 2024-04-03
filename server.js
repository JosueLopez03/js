const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const argon2 = require('argon2');
const crypto = require('crypto');
const dotenv = require('dotenv').config();

const app = express();
app.use(express.json());
const port = 8080;

// Define database here
const db = new sqlite3.Database('totally_not_my_privateKeys.db');
// get access to private key for encryption
const AES_KEY = process.env.NOT_MY_KEY;

let keyPair;
let expiredKeyPair;
let token;
const iv = crypto.randomBytes(16);

async function generateKeyPairs() {
  try {
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });

    // Save key pairs to the database
    saveKeyPairToDB(keyPair, Date.now() + 3600); // Expiry in 1 hour
    saveKeyPairToDB(expiredKeyPair, Date.now() - 3600); // Expiry in the past (expired)
  } catch (error) {
    console.error('Error generating key pairs:', error.message);
    process.exit(1);
  }
}

function generateToken(payload) {
  const options = {
    algorithm: 'RS256',
    expiresIn: "1h"
  };

  try {
    token = jwt.sign(payload, keyPair.toPEM(true), options);
  } catch (error) {
    console.error('Error generating token:', error.message);
    throw error;
  }
}


// Function to generate a secure password using UUIDv4
function generateSecurePassword() {
  return { password: uuidv4() };
}

// Encrypt private key using AES encryption
function encryptPrivateKey(privateKey) {
  const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(AES_KEY), iv);
  let encrypted = cipher.update(privateKey, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted.toString('hex');
}

// Decrypt private key using AES decryption
function decryptPrivateKey(encryptedKey) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(AES_KEY), iv);
  let decrypted = decipher.update(encryptedKey, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// database operations
function Database() {
  db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)', (error) => {
    if (error) {
      console.error('Error creating keys table:', error.message);
      process.exit(1);
    }
  });
  db.run('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, email TEXT UNIQUE, date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP, last_login TIMESTAMP)', (error) => {
    if (error) {
      console.error('Error creating users table:', error.message);
      process.exit(1);
    }
  }); //create users table
  db.run('CREATE TABLE IF NOT EXISTS auth_logs(id INTEGER PRIMARY KEY AUTOINCREMENT, request_ip TEXT NOT NULL, request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP, user_id INTEGER, FOREIGN KEY(user_id) REFERENCES users(id));', (error) => {
    if (error) {
      console.error('Error creating auth_logs table:', error.message);
      process.exit(1);
    }
  }); // create auth_logs table
}

// Function to save a key pair to the database
function saveKeyPairToDB(keyPair, exp) {
  const pemKey = keyPair.toPEM(true); // Serialize key to PEM format
  const encryptedKey = encryptPrivateKey(pemKey); // Encrypt private key
  // Insert encrypted key pair into the database
  db.run('INSERT INTO keys(key, exp) VALUES (?, ?)', [encryptedKey, exp], (err) => {
    if (err) {
      console.error('Error saving key to DB:', err.message);
      throw err;
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
        reject(err);
      } else {
        // Deserialize keys and return
        const validKeys = rows.map(row => {
          const decryptedKey = decryptPrivateKey(row.key);
          return jose.JWK.asKey(decryptedKey);
        });
        resolve(validKeys);
      }
    });
  });
}

app.all('/auth', (req, res, next) => {
  if (req.method !== 'POST') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.all('/.well-known/jwks.json', (req, res, next) => {
  if (req.method !== 'GET') {
    return res.status(405).send('Method Not Allowed');
  }
  next();
});

app.get('/.well-known/jwks.json', async (req, res) => {
  try {
    // Retrieve all valid keys from the database
    const keys = await getAllValidKeysFromDB();
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys }); // Return keys in JWKS format
  } catch (err) {
    console.error('Error retrieving JWKS:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth', async (req, res) => {
  try {
    const requestIp = req.ip;
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ error: "Username and password are required." });
    }

    const getUserIdQuery = 'SELECT id FROM users WHERE username = ?';
    // Wrap the entire logic in an async function
    const getUserId = async () => {
      return new Promise((resolve, reject) => {
        db.get(getUserIdQuery, [username], (error, row) => {
          if (error) {
            reject(error);
          } else {
            resolve(row ? row.id : null);
          }
        });
      });
    };

    try {
      const userId = await getUserId();

      if (!userId) {
        res.status(404).send('User not found');
        return;
      }

      const insertAuthLogQuery = 'INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)';
      await new Promise((resolve, reject) => {
        db.run(insertAuthLogQuery, [requestIp, userId], (error) => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        });
      });

      // User is considered authenticated by default as per rubric
      const expired = req.query.expired === "true";
      const payload = {
        username: username,
        password: password,
        expired: expired,
      };

      const accessToken = generateToken({username});
      res.json({ token: accessToken });

    } catch (error) {
      console.error('Error during authentication:', error);
      res.status(500).send('Internal Server Error');
    }
  } catch (error) {
    console.error('Error during authentication:', error);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/register', async (req, res) => {
  try {
    const { username, email } = req.body;
    const generatedPassword = generateSecurePassword();

    try {
      const hashedPassword = await argon2.hash(generatedPassword.password);
      const insertUserQuery = 'INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)';
      await new Promise((resolve, reject) => {
        db.run(insertUserQuery, [username, hashedPassword, email], (error) => {
          if (error) {
            if (error.message.includes('UNIQUE constraint failed')) {
              res.status(400).send('Username or email is already taken.');
            } else {
              reject(error);
            }
          } else {
            res.status(200).json({ password: generatedPassword.password });
            resolve();
          }
        });
      });
    } catch (error) {
      console.error('Error during password hashing or user registration:', error);
      res.status(500).send('Internal Server Error');
    }
  } catch (error) {
    console.error('Error during user registration:', error);
    res.status(500).send('Internal Server Error');
  }
});

db.serialize(() => {
  Database();
  generateKeyPairs().then(() => {
    app.listen(port, () => {
      console.log(`Server started on http://localhost:${port}`);
    });
  });
});

