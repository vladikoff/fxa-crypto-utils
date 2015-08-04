/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var fs = require('fs');
require('browserid-crypto/lib/algs/rs');
var b64 = require('./index').b64;
var hex2b64urlencode = require('./index').hex2b64urlencode;

var TOKEN_VALIDITY_MS = 1000 * 60 * 60 * 6; // 6 hours

var PREVERIFIED_EMAIL_TOKEN_TYPE = 'mozilla/fxa/preVerifyToken/v1';

function millisecondsToSeconds(milliseconds) {
  return Math.floor(milliseconds / 1000);
}

function invalidConfigError(msg) {
  throw new Error(msg);
}

function generateToken(email, jku, secretKey, kid, audience, validityMS) {
  var header = b64(JSON.stringify({
      alg: 'RS256',
      jku: jku,
      kid: kid
  }));

  var payload = b64(JSON.stringify({
      exp: millisecondsToSeconds(Date.now() + validityMS),
      aud: audience,
      sub: email,
      typ: PREVERIFIED_EMAIL_TOKEN_TYPE
  }));

  var sig = secretKey.sign(header + '.' + payload);
  var token = header + '.' + payload + '.' + hex2b64urlencode(sig);

  return token;
}

function PreverifiedEmailTokenGenerator(config) {
  config = config || {};

  if (config.keyPair) {
    this._keyPair = config.keyPair;
  } else {
    invalidConfigError('keyPair must be specified');
  }

  if (config.secretKeyId) {
    this._secretKeyId = config.secretKeyId;
  } else {
    invalidConfigError('secretKeyId must be specified');
  }

  if (config.audience) {
    this._audience = config.audience;
  } else {
    invalidConfigError('audience must be specified');
  }

  if (config.jku) {
    this._jku = config.jku;
  } else {
    invalidConfigError('jku must be specified');
  }
}

PreverifiedEmailTokenGenerator.prototype = {
  /**
   * Generate a preverified email token for the given email address.
   *
   * @param {string} email
   * @return {string} token
   */
  generate: function (email) {
    var self = this;

    return this._keyPair.getSecretKey()
      .then(function (secretKey) {
        return generateToken(email, self._jku, secretKey,
                               self._secretKeyId, self._audience,
                               TOKEN_VALIDITY_MS);
      });
  }
};

module.exports = PreverifiedEmailTokenGenerator;
