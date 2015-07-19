/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var browseridCrypto = require('browserid-crypto');
var b64 = require('./index').b64;

var fs = require('fs');
var Promises = require('bluebird');

var bignum = require('bignum');

var writeFile = Promises.promisify(fs.writeFile);
var generateKeypair = Promises.promisify(browseridCrypto.generateKeypair);

function KeyPair(config) {
  config = config || {};

  if (config.secretKey) {
    this._secretKey = config.secretKey;
  } else if (config.secretKeyFile) {
    var serializedSecretKey = fs.readFileSync(config.secretKeyFile);
    this._secretKey = browseridCrypto.loadSecretKey(serializedSecretKey);
  }

  if (config.publicKey) {
    this._publicKey = config.publicKey;
  } else if (config.publicKeyFile) {
    var serializedPublicKey = fs.readFileSync(config.publicKeyFile);
    this._publicKey = browseridCrypto.loadPublicKey(serializedPublicKey);
  }
}

function ensureKeypair() {
  //jshint validthis: true
  if (! (this._publicKey && this._secretKey)) {
    // generate an ephemeral keypair
    return this.generate()
      .then(function (keypair) {
        this._publicKey = keypair.publicKey;
        this._secretKey = keypair.secretKey;
        return keypair;
      }.bind(this));
  } else {
    return Promises.resolve({
      publicKey: this._publicKey,
      secretKey: this._secretKey
    });
  }
}

KeyPair.prototype = {
  generate: function () {
    return generateKeypair({
      algorithm: 'RS',
      keysize: 256
    });
  },

  getPublicKey: function () {
    return ensureKeypair.call(this)
      .then(function (keypair) {
        return keypair.publicKey;
      });
  },

  serializePublicKey: function () {
    return ensureKeypair.call(this)
      .then(function (keypair) {
        return keypair.publicKey.serialize();
      });
  },

  writePublicKey: function (publicKeyFile) {
    return this.serializePublicKey()
      .then(function (serializedPublicKey) {
        return writeFile(publicKeyFile, serializedPublicKey);
      });
  },

  getSecretKey: function () {
    return ensureKeypair.call(this)
      .then(function (keypair) {
        return keypair.secretKey;
      });
  },

  serializeSecretKey: function () {
    return ensureKeypair.call(this)
      .then(function (keypair) {
        return keypair.secretKey.serialize();
      });
  },

  writeSecretKey: function (secretKeyFile) {
    return this.serializeSecretKey()
      .then(function (serializedSecretKey) {
        return writeFile(secretKeyFile, serializedSecretKey);
      });
  },

  toPublicKeyResponseObject: function (secretKeyId) {
    return this.getPublicKey()
      .then(function (publicKey) {
        publicKey = publicKey.rsa;

        return {
          kid: secretKeyId,
          use: 'sig',
          kty: 'RSA',
          n: b64(bignum(publicKey.n).toBuffer()),
          e: b64(bignum(publicKey.e).toBuffer())
        };
      });
  }
};

module.exports = KeyPair;
