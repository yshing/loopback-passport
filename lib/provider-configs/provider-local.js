// var crypto = require('crypto');
module.exports = function(app, self) {
  'use strict';
  var localCallbackPool = {
    verifier: function(req, username, password, done) {
      var query = {
        where: {
          or: [{
            username: username
          }, {
            email: username
          }]
        }
      };
      self.userModel.findOne(query, function(err, user) {
        // Some error occur
        if (err) {
          return done(err);
        }
        // if a user is found
        if (user) {
          var u = user.toJSON();
          delete u.password;
          var userProfile = {
            provider: 'local',
            id: u.id,
            username: u.username,
            emails: [{
              value: u.email
            }],
            status: u.status,
            accessToken: null
          };

          user.hasPassword(password, function(err, ok) {
            if (ok) {
              done(null, user, u);
            } else {
              return done(null, false, {
                message: 'Incorrect password.'
              });
            }
          });
        } else {
          // UserNotFound
          console.info('UserNotFound');
          return done(null, false, {
            message: 'Incorrect username/email.'
          });
        }
      });
    },
    register: function(req, res, credential, fn) {
      var date = new Date();
      var userObj = {
        username: credential.username,
        password: credential.password,
        email: credential.email
      };
      return self.userModel.create(userObj, function(err, user) {
        if (err) {
          return fn(err);
        }
        var tokenHandler = function(err, token) {
          if (err) {
            return fn(err);
          }
          token.__data.user = user;
          fn(err, token);
        };
        // self.userPassportModel.create({
        user.passports.create({
          provider: 'local',
          externalId: user.id,
          credential: {
            username: user.username,
            email: user.email,
            password: user.password
          },
          created: date,
          modified: date
        }, function(err, passport) {
          if (err) {
            return fn(err);
          }
          if (passport) {
            return user.createAccessToken(credential.ttl, tokenHandler);
          }
        });

      });
    }
  };
  /**
   * Setup the local Provider here
   */
  self.authProviderModel.configureProvider('local', {
    provider: 'local',
    module: 'passport-local',
    isLocal: true,
    providerSettings: {
      usernameField: 'username',
      passwordField: 'password',
      failureFlash: true
    },
    actionSettings: {
      login: {
        successRedirect: '/auth/account',
        failureRedirect: '/local'
      }
    },
    callbackPool: localCallbackPool
  });

};
