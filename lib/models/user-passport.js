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
  'use strict';
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
    // setMethodsVisibility(UserPassportModel,[]);
    return UserPassportModel;
  };


  return UserPassport.setup();
};
