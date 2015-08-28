/*
 * Internal utilities for models
 */
var crypto = require('crypto');
var assert = require('assert');

/**
 * Get the model class
 * @param {Function} cls The sub class
 * @param {Function} base The base class
 * @returns {Function} The resolved class
 */
function getModel(cls, base) {
  'use strict';
  if (!cls) {
    return base;
  }
  return (cls.prototype instanceof base)? cls: base;
}

/**
 * Generate a key
 * @param {String} hmacKey The hmac key, default to 'loopback'
 * @param {String} algorithm The algorithm, default to 'sha1'
 * @param {String} encoding The string encoding, default to 'hex'
 * @returns {String} The generated key
 */
function generateKey(hmacKey, algorithm, encoding) {
  'use strict';
  assert(hmacKey, 'HMAC key is required');
  algorithm = algorithm || 'sha1';
  encoding = encoding || 'hex';
  var hmac = crypto.createHmac(algorithm, hmacKey);
  var buf = crypto.randomBytes(32);
  hmac.update(buf);
  var key = hmac.digest(encoding);
  return key;
}

function mRequire(id){
  'use strict';
  try {
    return require(id);
  } 
  catch(e){
      for (var parent = module.parent; parent; parent = parent.parent) {
        try {
          return parent.require(id);
        } catch(ex) {}
      }
      throw new Error('Cannot find module \'' + id + '\' from parent');
  }
}

exports.getModel = getModel;
exports.generateKey = generateKey;
exports.mRequire = mRequire;