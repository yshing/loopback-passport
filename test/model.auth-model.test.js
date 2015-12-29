var m = require('./init');
var loopback = require('loopback');
var assert = require('assert');
var AuthProvider = m.AuthProvider;
var User = loopback.User;

before(function (done) {
  // User.destroyAll(done);
  done();
});
describe('AuthProvider', function () {
	it('Should able to add new Providers', function (done) {
		AuthProvider.use('local','local');
		assert(Array.isArray(AuthProvider.list()),'return a Array');
		console.log(AuthProvider.list());
		done();
	});
});