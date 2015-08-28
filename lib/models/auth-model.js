/*!
 * Module Dependencies
 */

var mRequire = require('../utils').mRequire;
var _ = require('underscore');

/**
 * AuthProvider model
 * Extends Loopback [Model]
 * @return {Loopback Model}
 */
module.exports = function(AuthModel) {
  'use strict';
  var passport = require('passport');
  var AvailableStrategies = [];
  var HiddenStaregies = ['session'];


  AuthModel._passport = passport;
  AuthModel.related = {};
  function customErrorHandler(ctx,callbacks,fn){
    return function(){
      if (typeof callbacks[arguments[1].code] === 'function'){
        callbacks[arguments[1].code](ctx.req,ctx.res,fn);
      } else {
        fn.apply(this,arguments);
      }
    };
  }
  function passportCallbackTranslator(fn,afterVerify) {
    return function callbackTranslator() {
      switch (arguments.length) {
        case 2:
          // Passport strategy.error
          // passport/lib/middleware/authenticate.js #333 :return callback(error)
          if (arguments[1].id) {
            afterVerify(arguments[1]);
          } else {
            fn.apply(this, arguments);
          }
          break;
        case 3:
          //return callback(null, user, info);
          if (!arguments[1]) {
            var UserNotFound = new Error('User not found');
            UserNotFound.statusCode = 404;
            UserNotFound.code = 'USER_NOT_FOUND';
            fn(UserNotFound);

          } else if (arguments[1].id) {
            // if LoginSuccess
            // afterVerify(err, user, fn);
            if(typeof afterVerify === 'function'){ 
              afterVerify(null, arguments[1], fn);
            } else {
              fn.apply(this, arguments);
            }
          } else {
            fn(null, {
              user: arguments[1],
              info: arguments[2]
            });
          }
          break;
        default:
          //passport/lib/middleware/authenticate.js #84 :return callback(null, false, challenges, statuses);
          if(arguments[0] instanceof Error){
            fn(arguments[0]);
          }else {
            var PassportLoginFail = new Error('Passport login failed.');
            PassportLoginFail.statusCode = 400;
            PassportLoginFail.message = arguments[2].message || 'Passport login failed';
            PassportLoginFail.code = 'PASSPORT_LOGIN_FAIL';
            fn(PassportLoginFail);
          }
          break;
      }
    };
  }
  AuthModel.passportTranslator = passportCallbackTranslator;
  /**
   * Mapping passport.js authentication to Loopback default login beheavior.
   * 
   * @param  {Object}   ctx Loopback remote context
   * @param  {String}   Provider Provider name.
   * @param  {Object}   credentials The login credentials.
   * @param  {String[]|String}   
   * @param  {Function} callback Callback function
   * @param {Error} err Error object
   * @param {AccessToken} token Access token if login is successful
   */
  AuthModel.login = function(ctx, Provider, credentials, include, fn) {
    // Provider = Provider || 'local';
    var thisProvider = passport._strategies[Provider];
    if (!thisProvider || HiddenStaregies.indexOf(Provider) >= 0) {
      // ProviderNotFound
      var ProviderNotFound = new Error('Provider not found.');
      ProviderNotFound.statusCode = 400;
      ProviderNotFound.code = 'PROVIDER_NOT_FOUND';
      fn(ProviderNotFound);
      return fn.promise;
    }
    var thisProviderOptions = thisProvider.ProviderOptions;
    ctx.req.AuthInfo = {
      method: 'login',
      provider: Provider,
      callback: fn
    };
    
    // Retrun the token after user is found.
    function afterVerify(err, user, fn) {
      // tokenHandler from Loopback default User Model
      function tokenHandler(err, token) {
        if (err){ return fn(err); }
        if (Array.isArray(include) ? include.indexOf('user') !== -1 : include === 'user') {
          token.__data.user = user;
        }
        fn(err, token);
      }

      if (AuthModel.settings.emailVerificationRequired && !user.emailVerified) {
        // Fail to log in if email verification is not done yet
        debug('User email has not been verified');
        err = new Error('login failed as the email has not been verified');
        err.statusCode = 401;
        err.code = 'LOGIN_FAILED_EMAIL_NOT_VERIFIED';
        fn(err);
      } else {
        if (user.createAccessToken.length === 2) {
          user.createAccessToken(credentials.ttl, tokenHandler);
        } else {
          user.createAccessToken(credentials.ttl, credentials, tokenHandler);
        }
      }
    }
    // Construct the callback translator
    var callbackTranslator = passportCallbackTranslator(fn,afterVerify);

    var loginSettings, loginSuccessCallback;

    if (typeof thisProviderOptions.actionSettings.login === 'function'){
      loginSettings = thisProviderOptions.actionSettings.login.call(ctx.req);
    } else {
      loginSettings = thisProviderOptions.actionSettings.login || {};
    }

    if (thisProviderOptions.isLocal) {
      loginSuccessCallback = thisProviderOptions.callbackPool.loginSuccessCallback || callbackTranslator;
      passport.authenticate(Provider, loginSettings, callbackTranslator)(ctx.req, ctx.res, fn);
    } else {
      passport.authenticate(Provider)(ctx.req, ctx.res);
    }
  };
  /**
   * LoginCallback Remote Method for non-local passports.
   * 
   * @param  {[type]}   ctx      [description]
   * @param  {[type]}   Provider [description]
   * @param  {Function} fn       [description]
   * @return {[type]}            [description]
   */
  AuthModel.loginCallback = function(ctx,Provider,fn){
    var thisProvider = passport._strategies[Provider];
    if (!thisProvider || HiddenStaregies.indexOf(Provider) >= 0) {
      // ProviderNotFound
      var ProviderNotFound = new Error('Provider not found.');
      ProviderNotFound.statusCode = 404;
      ProviderNotFound.code = 'PROVIDER_NOT_FOUND';
      fn(ProviderNotFound);
      return fn.promise;
    }
    ctx.req.AuthInfo = {
      method: 'loginCallback',
      provider: Provider,
      callback: fn
    };
    
    function afterVerify(err, user, fn) {
      // tokenHandler from Loopback default User Model
      function tokenHandler(err, token) {
        if (err){ return fn(err); }
        token.__data.user = user;
        fn(err, token);
      }
      if (AuthModel.settings.emailVerificationRequired && !user.emailVerified) {
        // Fail to log in if email verification is not done yet
        debug('User email has not been verified');
        err = new Error('login failed as the email has not been verified');
        err.statusCode = 401;
        err.code = 'LOGIN_FAILED_EMAIL_NOT_VERIFIED';
        fn(err);
      } else {
        // Loopback default User.createAccessToken(ttl,tokenHandler);
        user.createAccessToken(undefined, tokenHandler);
      }
    }
    var callbackTranslator = passportCallbackTranslator(fn,afterVerify);
    passport.authenticate(Provider,callbackTranslator)(ctx.req,ctx.res);
  };

  AuthModel.signUp = function(ctx, Provider, credentials, fn) {
    ctx.req.AuthInfo = {
      method: 'signUp',
      provider: Provider,
      callback: fn
    };
    var thisProvider = passport._strategies[Provider];
    if (!thisProvider || HiddenStaregies.indexOf(Provider) >= 0) {
      // ProviderNotFound
      var ProviderNotFound = new Error('Provider not found.');
      ProviderNotFound.statusCode = 400;
      ProviderNotFound.code = 'PROVIDER_NOT_FOUND';
      fn(ProviderNotFound);
      return fn.promise;
    }
    var register = thisProvider.ProviderOptions.callbackPool.register;
    if (typeof register === 'function'){
      try {
        register(ctx.req,ctx.res,credentials,fn);
      } catch (e){
        if( e instanceof Error) { return fn(e); } else {
          var err = new Error('Error when calling register');
          err.code = 'REGISTER_ERROR';
          err.statusCode = 503;
          return fn(err);
        }
      }
    } else {
      var err = new Error('Provider register callback not found.');
      err.code = 'REGISTER_NOT_FOUND';
      err.statusCode = 503;
      fn(err);
    }

  };
  AuthModel.signUpCallback = function(ctx,Provider,fn){
    ctx.req.AuthInfo = {
      method: 'signUpCallback',
      provider: Provider,
      callback: fn
    };
    var credentials = ctx.req.session.credentials || {};
    var thisProvider = passport._strategies[Provider];
    if (!thisProvider || HiddenStaregies.indexOf(Provider) >= 0) {
      // ProviderNotFound
      var ProviderNotFound = new Error('Provider not found.');
      ProviderNotFound.statusCode = 400;
      ProviderNotFound.code = 'PROVIDER_NOT_FOUND';
      fn(ProviderNotFound);
      return fn.promise;
    }
    var registerCallback = thisProvider.ProviderOptions.callbackPool.registerCallback;
    if (typeof registerCallback === 'function'){
      try {
        registerCallback(ctx.req,ctx.res,credentials,fn);
      } catch (e){
        if( e instanceof Error) { return fn(e); } else {
          var err = new Error('Error when calling registerCallback');
          err.code = 'REGISTER_CALLBACK_ERROR';
          err.statusCode = 503;
          return fn(err);
        }
      }
    } else {
      var err = new Error('Provider registerCallback callback not found.');
      err.code = 'REGISTER_CALLBACK_NOT_FOUND';
      err.statusCode = 503;
      fn(err);
    }
  };

  AuthModel.auth = function(){
    return AuthModel._passport.authenticate.apply(AuthModel._passport,arguments);
  };
  
  AuthModel.getCurrentUser = function(fn){

  };

  AuthModel.logout = function(fn) {};

  AuthModel.use = function() {
    AuthModel._passport.use.apply(AuthModel._passport, arguments);

    AvailableStrategies = Object.keys(passport._strategies).filter(function(str) {
      return HiddenStaregies.indexOf(str) < 0;
    });
  };

  AuthModel.unuse = function(provider){
    var providerIndex = AvailableStrategies.indexOf(provider);
    if (providerIndex >= 0){
      AuthModel._passport.unuse(provider);
      return true;
    }
    return false;
  };

  AuthModel.list = function(fn) {
    if(typeof fn === 'function'){ 
      fn(null, AvailableStrategies);
    } else {
      return AvailableStrategies;
    }
  };
  
  /**
   * Adding new provider to AuthModel.
   * 
   * @param  {[type]}
   * @param  {[type]}
   * @return {[type]}
   */
  AuthModel.configureProvider = function(ProviderName, ProviderOptions) {
    var AuthStrategy = mRequire(ProviderOptions.module);

    AuthModel._passport.use(ProviderName,
      new AuthStrategy(_.defaults(
      {
        passReqToCallback: true
      },
      ProviderOptions.providerSettings),
      ProviderOptions.callbackPool.verifier)
    );
    AuthModel._passport._strategies[ProviderName].ProviderOptions = ProviderOptions;

    AvailableStrategies = Object.keys(AuthModel._passport._strategies).filter(function(str) {
      return HiddenStaregies.indexOf(str) < 0;
    });
  };
  
  AuthModel.setup = function() {

    AuthModel.base.setup.call(this);

    var resultAuthProvider = this;
    // Remote Method Login:
    resultAuthProvider.remoteMethod('login', {
      description: 'Login user with .',
      accessType: 'READ',
      accepts: [{
        arg: 'ctx',
        type: 'object',
        description: 'Various login credentials.',
        http: {
          source: 'context'
        }
      }, {
        arg: 'Provider',
        type: 'string',
        description: 'ProviderName',
        required: true
      }, {
        arg: 'credentials',
        type: 'object',
        required: false,
        http: {
          source: 'body'
        }
      }, {
        arg: 'include',
        type: ['string'],
        http: {
          source: 'query'
        },
        description: 'Related objects to include in the response. ' +
          'See the description of return value for more details.'
      }],
      returns: {
        arg: 'accessToken',
        type: 'object',
        root: true,
        description: 'The response body contains properties of the AccessToken created on login.\n' +
          'Depending on the value of `include` parameter, the body may contain ' +
          'additional properties:\n\n' +
          '  - `user` - `{User}` - Data of the currently logged in user. (`include=user`)\n\n'
      },
      http: [{
        verb: 'all',
        path: '/:Provider/login'
      }]
    });
    
    resultAuthProvider.remoteMethod('loginCallback', {
      description: 'Login callback user with .',
      accessType: 'READ',
      accepts: [{
        arg: 'ctx',
        type: 'object',
        description: 'Various login credentials.',
        http: {
          source: 'context'
        }
      }, {
        arg: 'Provider',
        type: 'string',
        description: 'ProviderName',
        required: true
      }],
      returns: {
        arg: 'accessToken',
        type: 'object',
        root: true,
        description: 'The response body contains properties of the AccessToken created on login.\n' +
          'Depending on the value of `include` parameter, the body may contain ' +
          'additional properties:\n\n' +
          '  - `user` - `{User}` - Data of the currently logged in user. (`include=user`)\n\n'
      },
      http: [{
        verb: 'get',
        path: '/:Provider/login/callback'
      },{
        verb: 'get',
        path: '/:Provider/callback'
      }
      ]
    });

    /**
     * remoteMethod 'list' default method of this Model
     * returns a array of avalible providers.
     */
    resultAuthProvider.remoteMethod('list', {
      description: 'List avaliable Passport providers. ',
      accessType: 'READ',
      accepts: [],
      returns: {
        arg: 'strategies',
        type: 'array'
      },
      http: [{
        verb: 'get',
        path: '/'
      }]
    });
    resultAuthProvider.remoteMethod('signUp',{
      description: 'SignUp with the required stretegy.',
      accessType: 'WRITE',
      accepts: [{
        arg: 'ctx',
        type: 'object',
        description: 'Various login credentials.',
        http: {
          source: 'context'
        }
      }, {
        arg: 'Provider',
        type: 'string',
        description: 'ProviderName',
        required: true
      }, {
        arg: 'credentials',
        type: 'object',
        required: false,
        http: {
          source: 'body'
        }
      }],
      returns: {
        arg: 'accessToken',
        type: 'object',
        root: true,
        description: 'The response body contains properties of the AccessToken created on login.\n' +
          // 'Depending on the value of `include` parameter, the body may contain ' +
          'the body also contains additional properties:\n\n' +
          '  - `user` - `{User}` - Data of the currently logged in user. (`include=user`)\n\n'
      },
      http: [{
        verb: 'post',
        path: '/:Provider/signUp'
      },
      {
        verb: 'get',
        path: '/:Provider/signUp'
      }
      ]
    });
    
    resultAuthProvider.remoteMethod('signUpCallback', {
      description: 'SignUp callback user with passport .',
      accessType: 'READ',
      accepts: [{
        arg: 'ctx',
        type: 'object',
        description: 'Various login credentials.',
        http: {
          source: 'context'
        }
      }, {
        arg: 'Provider',
        type: 'string',
        description: 'ProviderName',
        required: true
      }],
      returns: {
        arg: 'accessToken',
        type: 'object',
        root: true,
        description: 'The response body contains properties of the AccessToken created on login.\n' +
          'Depending on the value of `include` parameter, the body may contain ' +
          'additional properties:\n\n' +
          '  - `user` - `{User}` - Data of the currently logged in user. (`include=user`)\n\n'
      },
      http: [{
        verb: 'get',
        path: '/:Provider/signUp/callback'
      }]
    });

    return resultAuthProvider;
  };


  return AuthModel.setup();
};
