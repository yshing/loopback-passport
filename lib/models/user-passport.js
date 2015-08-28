/**
 * Tracks third-party logins and profiles.
 *
 * @param {String} provider   Auth provider name, such as facebook, google, twitter, linkedin.
 * @param {String} authScheme Auth scheme, such as oAuth, oAuth 2.0, OpenID, OpenID Connect.
 * @param {String} externalId Provider specific user ID.
 * @param {Object} profile User profile, see http://passportjs.org/guide/profile.
 * @param {Object} credentials Credentials.  Actual properties depend on the auth scheme being used:
 *
 * - oAuth: token, tokenSecret
 * - oAuth 2.0: accessToken, refreshToken
 * - OpenID: openId
 * - OpenID: Connect: accessToken, refreshToken, profile
 * @param {*} userId The LoopBack user ID.
 * @param {Date} created The created date
 * @param {Date} modified The last modified date
 *
 * @class
 * @inherits {DataModel}
 */
 module.exports = function(UserPassport) {
  var loopback = require('loopback');
  var utils = require('../utils');
  /*!
   * Create an access token for the given user
   * @param {User} user The user instance
   * @param {Number} [ttl] The ttl in millisenconds
   * @callback {Function} cb The callback function
   * @param {Error|String} err The error object
    * param {AccessToken} The access token
   */
  function createAccessToken(user, ttl, cb) {
    if (arguments.length === 2 && typeof ttl === 'function') {
      cb = ttl;
      ttl = 0;
    }
    user.accessTokens.create({
      created: new Date(),
      ttl: Math.min(ttl || user.constructor.settings.ttl,
        user.constructor.settings.maxTTL)
    }, cb);
  }

  function profileToUser(provider, profile, options) {
  // Let's create a user for that
    var email = profile.emails && profile.emails[0] && profile.emails[0].value;
    if (!email && !options.emailOptional) {
      // Fake an e-mail
      email = (profile.username || profile.id) + '@loopback.' +
              (profile.provider || provider) + '.com';
    }
    var username = provider + '.' + (profile.username || profile.id);
    var password = utils.generateKey('password');
    var userObj = {
      username: username,
      password: password
    };
    if (email) {
      userObj.email = email;
    }
    return userObj;
  }

  UserPassport.signUp = function(profile,fn){
    UserPassport.Create({});
  };
  UserPassport.setup = function(){
    UserPassport.base.setup.call(this);
    var UserPassportModel = this;
    /**
     * Hides all the methods besides those in 'methods'.
     *
     * @param Model model to be updated.
     * @param methods array of methods to expose, e.g.: ['find', 'updateAttributes'].
     */
    var setMethodsVisibility = function(Model, methods) {
      methods = methods || [];
      Model.sharedClass.methods().forEach(function(method) {
        method.shared = methods.indexOf(method.name) > -1;
      });
    };
    setMethodsVisibility(UserPassportModel,[]);
    return UserPassportModel;
  };
  /**
   * Link a third party account to a LoopBack user
   * @param {String} provider The provider name
   * @param {String} authScheme The authentication scheme
   * @param {Object} profile The profile
   * @param {Object} credentials The credentials
   * @param {Object} [options] The options
   * @callback {Function} cb The callback function
   * @param {Error|String} err The error object or string
   * @param {Object} [credential] The user credential object
   */
  // UserPassport.link = function (userId, provider, authScheme, profile,
  //                                 credentials, options, cb) {
  //   options = options || {};
  //   if(typeof options === 'function' && cb === undefined) {
  //     cb = options;
  //     options = {};
  //   }
  //   var UserPassportModel = utils.getModel(this, UserPassport);
  //   UserPassportModel.findOne({where: {
  //     userId: userId,
  //     provider: provider,
  //     externalId: profile.id
  //   }}, function (err, extCredential) {
  //     if (err) {
  //       return cb(err);
  //     }

  //     var date = new Date();
  //     if (extCredential) {
  //       // Find the user for the given extCredential
  //       extCredential.credentials = credentials;
  //       return extCredential.updateAttributes({profile: profile,
  //         credentials: credentials, modified: date}, cb);
  //     }

  //     // Create the linked account
  //     UserPassportModel.create({
  //       provider: provider,
  //       externalId: profile.id,
  //       authScheme: authScheme,
  //       profile: profile,
  //       credentials: credentials,
  //       userId: userId,
  //       created: date,
  //       modified: date
  //     }, function (err, i) {
  //       cb(err, i);
  //     });

  //   });
  // }


  return UserPassport.setup();
};
