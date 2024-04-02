const express = require('express');
const jwt = require('jsonwebtoken');
const jose = require('node-jose');
const sqlite3 = require('sqlite3');

const app = express();
const port = 8080;

const db = new sqlite3.Database('totally_not_my_privateKeys.db');

let keyPair;
let expiredKeyPair;
let token;
let expiredToken;

async function generateKeyPairs() {
  try {
    keyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
    expiredKeyPair = await jose.JWK.createKey('RSA', 2048, { alg: 'RS256', use: 'sig' });
  } catch (error) {
    console.error('Error generating key pairs:', error.message);
    process.exit(1);
  }
}

function generateToken() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyPair.kid
    }
  };

  try {
    token = jwt.sign(payload, keyPair.toPEM(true), options);
  } catch (error) {
    console.error('Error generating token:', error.message);
    process.exit(1);
  }
}

function generateExpiredJWT() {
  const payload = {
    user: 'sampleUser',
    iat: Math.floor(Date.now() / 1000) - 30000,
    exp: Math.floor(Date.now() / 1000) - 3600
  };
  const options = {
    algorithm: 'RS256',
    header: {
      typ: 'JWT',
      alg: 'RS256',
      kid: expiredKeyPair.kid
    }
  };

  try {
    expiredToken = jwt.sign(payload, expiredKeyPair.toPEM(true), options);
  } catch (error) {
    console.error('Error generating expired token:', error.message);
    process.exit(1);
  }
}

// database operations
function Database() {
  db.run('CREATE TABLE IF NOT EXISTS keys(kid INTEGER PRIMARY KEY AUTOINCREMENT,key BLOB NOT NULL,exp INTEGER NOT NULL)', (error) => {
    if (error) {
      console.error('Error creating keys table:', error.message);
      process.exit(1);
    }
    // Encrypt private keys before inserting into the database
    const insertKeyPairQuery = 'INSERT INTO keys(key, exp) VALUES(?, ?)';
    const currentTimestamp = Math.floor(Date.now() / 1000);
    db.run(insertKeyPairQuery, [keyPair.toPEM(true), currentTimestamp + 3600], (error) => {
      if (error) {
        console.error('Error inserting key pair:', error.message);
        process.exit(1);
      }
    });
    db.run(insertKeyPairQuery, [expiredKeyPair.toPEM(true), currentTimestamp - 3600], (error) => {
      if (error) {
        console.error('Error inserting expired key pair:', error.message);
        process.exit(1);
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

app.get('/.well-known/jwks.json', (req, res) => {
  try {
    const validKeys = [keyPair].filter(key => !key.expired);
    res.setHeader('Content-Type', 'application/json');
    res.json({ keys: validKeys.map(key => key.toJSON()) });
  } catch (error) {
    console.error('Error retrieving JWKS:', error.message);
    res.status(500).send('Internal Server Error');
  }
});

app.post('/auth', (req, res) => {
  try {
    if (req.query.expired === 'true') {
      return res.send(expiredToken);
    }
    res.send(token);
  } catch (error) {
    console.error('Error handling auth request:', error.message);
    res.status(500).send('Internal Server Error');
  }
});

generateKeyPairs().then(() => {
  generateToken();
  generateExpiredJWT();
  Database();
  app.listen(port, () => {
    console.log(`Server started on http://localhost:${port}`);
  });
});
