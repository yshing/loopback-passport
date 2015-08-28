var loopback = require('loopback');
var passport = require('passport');
var _ = require('underscore');
var mRequire = require('./utils').mRequire;

module.exports = (function() {
    'use strict';

    /**
     * The passport configurator
     * @param {Object} app The LoopBack app instance
     * @returns {PassportConfigurator}
     * @constructor
     * @class
     */
    function PassportConfigurator(app) {
        if (!(this instanceof PassportConfigurator)) {
            return new PassportConfigurator(app);
        }
        this.app = app;
    }

    /**
     * Set up data models for user identity/credential and application credential
     * @options {Object} options Options for models
     * @property {Model} [userModel] The user model class
     * @property {Model} [userCredentialModel] The user credential model class
     * @property {Model} [userPassport] The user identity model class
     * @end
     */
    PassportConfigurator.prototype.setupModels = function(options) {
        var defaultOptions = {
            userModel: loopback.getModelByType('User'),
            userPassportModel: loopback.getModelByType('UserPassport'),
            authProviderModel: loopback.getModelByType('AuthProvider')
        };
        options = _.extend(defaultOptions, options);

        // Set up relations
        this.userModel = options.userModel;
        this.userPassportModel = options.userPassportModel;
        this.authProviderModel = options.authProviderModel;

        this.authProviderModel.related.userModel = options.userModel;
        this.authProviderModel.related.userPassportModel = options.userPassportModel;

        if (!this.userModel.relations.passports) {
            this.userModel.hasMany(this.userPassportModel, {
                as: 'passports'
            });
        } else {
            this.userPassportModel = this.userModel.relations.passports.modelTo;
        }
        if (!this.userPassportModel.relations.user) {
            this.userPassportModel.belongsTo(this.userModel, {
                as: 'user'
            });
        }
    };

    /**
     * Initialize the passport configurator
     * @param {Boolean} noSession Set to true if no session is required
     * @returns {Passport}
     */
    PassportConfigurator.prototype.init = function(noSession) {
        var self = this;
        self.app.middleware('session:after', passport.initialize());

        if (!noSession) {
            self.app.middleware('session:after', passport.session());

            // Serialization and deserialization is only required if passport session is
            // enabled

            passport.serializeUser(function(user, done) {
                done(null, user.id);
            });

            passport.deserializeUser(function(id, done) {

                // Look up the user instance by id
                self.userModel.findById(id, function(err, user) {
                    // if (err || !user) {
                    return done(err, user);
                    // }

                    // user.identities(function(err, identities) {
                    //   user.profiles = identities;
                    //   user.credentials(function(err, accounts) {
                    //     user.accounts = accounts;
                    //     done(err, user);
                    //   });
                    // });
                });
            });
        }

        return passport;
    };
})();
