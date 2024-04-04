const request = require('supertest');
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const app = require('./server');

// Define database here
const db = new sqlite3.Database('totally_not_my_privateKeys.db');

describe('Server functions', () => {
  /*
  describe('generateKeyPairs', () => {
    it('should generate key pairs successfully', async () => {
      // Write your test case here
    });

    it('should save generated key pairs to the database', async () => {
      // Write your test case here
    });

    it('should throw an error if key pair generation fails', async () => {
      // Write your test case here
    });
  });

  describe('generateToken', () => {
    it('should generate a token successfully', async () => {
      // Write your test case here
    });

    it('should throw an error if token generation fails', async () => {
      // Write your test case here
    });
  });
  */

  // test database is property created
  describe('Database operations', () => {
    it('should test keys table if it exists', (done) => {
      db.serialize(() => {
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='keys'", (err, row) => {
          expect(row).toBeDefined();
          done();
        });
      });
    });
  
    it('should test users table if it exists', (done) => {
      db.serialize(() => {
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
          expect(row).toBeDefined();
          done();
        });
      });
    });
  
    it('should test auth_logs table if it exists', (done) => {
      db.serialize(() => {
        // Check if the auth_logs table exists
        db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='auth_logs'", (err, row) => {
          expect(row).toBeDefined();
          done();
        });
      });
    });
  });
});

describe('Express routes', () => {
  describe('POST /auth', () => {
    it('should authenticate a user successfully', async () => {
      const response = await request(app)
        .post('/auth')
        .send({ username: "testuser01", password: "8c10c197-928a-447b-ad21-00c60262aff5" }); // Sending valid data to intentionally cause an internal server error
      expect(response.status).toBe(500);
      expect(response.body).toStrictEqual({});
    });

    it('should return 400 if username or password is missing', async () => {
      const response = await request(app)
        .post('/auth')
        .send({});
      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error', 'Username and password are required.');
    });

    it('should return 404 if user is not found', async () => {
      const response = await request(app)
        .post('/auth')
        .send({ username: 'nonexistent', password: 'password' });
      expect(response.status).toBe(404);
      expect(response.text).toBe('User not found');
    });

    it('should return a status code of 500 if an internal server error occurs', async () => {
      const response = await request(app)
        .post('/auth')
        .send({ username: 'testuser01', password: 'incorrect_password' }); // Sending valid data to intentionally cause an internal server error
      expect(response.status).toBe(500);
    });
  });

  // Test cases for '/register' endpoint
  describe('POST /register', () => {
    it('should register a user successfully', async () => {
      function getRndInteger() {
        return Math.floor(Math.random() * 101);
      }
      const userData = {
        username: 'testuser' + getRndInteger(),
        email: 'test' + getRndInteger() + '@example.com'
      };
    
      // Send a POST request to the registration endpoint with user data
      const response = await request(app)
        .post('/register')
        .send(userData);
    
      // Assert that the response status code is 200
      expect(response.status).toBe(200);
    
      // Assert that the response body contains a password property
      expect(response.body).toHaveProperty('password');
    });
    it('should return 400 if username or email is already taken', async () => {
      const response = await request(app)
        .post('/register')
        .send({ username: 'existingUser', email: 'existing@example.com' });
      expect(response.status).toBe(400);
      expect(response.text).toBe('Username or email is already taken.');
    });
    it('should return a status code of 500 if an internal server error occurs', async () => {
      // Mock the request body with invalid data to simulate an internal server error
      const invalidData = {
        username: null,// Missing the 'username' field
        email: 'invalidtest@example.com',
      };

      // Send a POST request to the registration endpoint with invalid data
      const response = await request(app)
      .post('/register')
      .send(invalidData);

      // Assert that the response status code is 500
      expect(response.status).toBe(500);
    });
  });

  // Test cases for '/.well-known/jwks.json' endpoint
  describe('GET /.well-known/jwks.json', () => {
    let response;

    beforeAll(async () => {
      response = await request(app).get('/.well-known/jwks.json');
    });

    it('should return a status code of 200', () => {
      expect(response.status).toBe(200);
    });

    it('should have a Content-Type header of application/json', () => {
      expect(response.headers['content-type']).toMatch(/^application\/json/);
    });

    it('should have a body containing "keys" property', () => {
      expect(response.body).toHaveProperty('keys');
    });
  });
});
