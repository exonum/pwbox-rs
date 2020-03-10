#!/usr/bin/env node

const { strict: assert } = require('assert');
const crypto = require('crypto');
const { Pwbox } = require('./pkg');

const box = new Pwbox({ fillBytes: crypto.randomFillSync });
const password = 'correct horse battery staple';
const data = crypto.randomBytes(32);
console.log('Original data:', data);
const encrypted = box.encrypt(password, data);
console.log('Encrypted data:', encrypted);
const decrypted = Buffer.from(box.decrypt(password, encrypted));
console.log('Decrypted data:', decrypted);
assert.equal(decrypted.length, data.length);
assert.ok(decrypted.every((byte, i) => byte === data[i]));
