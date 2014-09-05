/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var jwcrypto = require('jwcrypto');
var b64 = require('jwcrypto/lib/utils').base64urlencode;

var fs = require('fs');
var Promises = require('bluebird');
var bigint = require('bigint');

var writeFile = Promises.promisify(fs.writeFile);
var generateKeypair = Promises.promisify(jwcrypto.generateKeypair);

function KeyPair(config) {
  config = config || {};

  if (config.secretKey) {
    this._secretKey = config.secretKey;
  } else if (config.secretKeyFile) {
    var serializedSecretKey = fs.readFileSync(config.secretKeyFile);
    this._secretKey = jwcrypto.loadSecretKey(serializedSecretKey);
  }

  if (config.publicKey) {
    this._publicKey = config.publicKey;
  } else if (config.publicKeyFile) {
    var serializedPublicKey = fs.readFileSync(config.publicKeyFile);
    this._publicKey = jwcrypto.loadPublicKey(serializedPublicKey);
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
          n: b64(bigint(publicKey.n).toBuffer()),
          e: b64(bigint(publicKey.e).toBuffer())
        };
      });
  }
};

module.exports = KeyPair;
