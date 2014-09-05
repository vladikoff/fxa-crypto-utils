/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var path = require('path');
var fs = require('fs');
var assert = require('assert');
var Promises = require('bluebird');
var FxaCryptoUtils = require('../../index');
var KeyPair = FxaCryptoUtils.KeyPair;

describe('KeyPair', function () {
  var keyPair;

  var SECRET_KEY_FILE = path.join(__dirname, 'secret-key.json');
  var PUBLIC_KEY_FILE = path.join(__dirname, 'public-key.json');

  describe('ephemeral keys', function () {
    before(function () {
      keyPair = new KeyPair();
    });

    after(function () {
      fs.unlinkSync(SECRET_KEY_FILE);
      fs.unlinkSync(PUBLIC_KEY_FILE);
    });

    describe('generate', function () {
      it('generates a public/private keypair', function () {
        return keyPair.generate()
          .then(function (keys) {
            assert.ok(keys);
          });
      });
    });

    describe('getPublicKey', function () {
      it('gets a public key', function () {
        return keyPair.getPublicKey()
          .then(function (publicKey) {
            assert.ok(publicKey);
          });
      });
    });

    describe('serializePublicKey', function () {
      it('gets a serialized public key', function () {
        return keyPair.serializePublicKey()
          .then(function (serializedKey) {
            assert.equal(typeof serializedKey, 'string');
          });
      });
    });

    describe('writePublicKey', function () {
      it('writes the public key to disk', function () {
        return keyPair.writePublicKey(PUBLIC_KEY_FILE)
          .then(function () {
            assert.equal(fs.existsSync(PUBLIC_KEY_FILE), true);
          });
      });
    });

    describe('getSecretKey', function () {
      it('gets a secret key', function () {
        return keyPair.getSecretKey()
          .then(function (secretKey) {
            assert.ok(secretKey);
          });
      });
    });

    describe('serializeSecretKey', function () {
      it('gets a serialized secret key', function () {
        return keyPair.serializeSecretKey()
          .then(function (serializedKey) {
            assert.equal(typeof serializedKey, 'string');
          });
      });
    });

    describe('writeSecretKey', function () {
      it('writes the secret key to disk', function () {
        return keyPair.writeSecretKey(SECRET_KEY_FILE)
          .then(function () {
            assert.equal(fs.existsSync(SECRET_KEY_FILE), true);
          });
      });
    });
  });

  describe('keys loaded from disk', function () {
    before(function () {
      var keyPairUsedToGenerate = new KeyPair();
      return keyPairUsedToGenerate.writeSecretKey(SECRET_KEY_FILE)
        .then(function () {
          return keyPairUsedToGenerate.writePublicKey(PUBLIC_KEY_FILE);
        })
        .then(function () {
          keyPair = new KeyPair({
            secretKeyFile: SECRET_KEY_FILE,
            publicKeyFile: PUBLIC_KEY_FILE
          });
        });
    });

    after(function () {
      fs.unlinkSync(SECRET_KEY_FILE);
      fs.unlinkSync(PUBLIC_KEY_FILE);
    });

    it('loads the public/private keys from disk', function () {
      return Promises.all([
        keyPair.serializePublicKey(),
        keyPair.serializeSecretKey()
      ]).spread(function (serializedPublicKey, serializedSecretKey) {
        assert.equal(serializedPublicKey, fs.readFileSync(PUBLIC_KEY_FILE));
        assert.equal(serializedSecretKey, fs.readFileSync(SECRET_KEY_FILE));
      });
    });
  });
});

