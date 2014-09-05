/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

'use strict';

var path = require('path');
var assert = require('assert');
var FxaCryptoUtils = require('../../index');
var PreverifiedEmailTokenGenerator = FxaCryptoUtils.PreverifiedEmailTokenGenerator;
var KeyPair = FxaCryptoUtils.KeyPair;

describe('PreverifiedEmailTokenGenerator', function () {
  var secretKeyPath = path.join(__dirname, '..', 'keys', 'secret-key.json');
  var generator;

  beforeEach(function () {
    var keyPair = new KeyPair();

    generator = new PreverifiedEmailTokenGenerator({
      keyPair: keyPair,
      secretKeyId: 'dev-1',
      // jku is where the corresponding public key can be found.
      jku: '127.0.0.1:9000/.well-known/public-keys',
      audience: 'https://accounts.firefox.com'
    });
  });

  it('creates a token', function () {
    return generator.generate('testuser@testuser.com')
      .then(function (token) {
        assert.ok(token);

        var pieces = token.split('.');
        assert.equal(pieces.length, 3);
      });
  });
});

