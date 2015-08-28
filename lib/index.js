var loopback = require('loopback');
var DataModel = loopback.PersistedModel || loopback.DataModel;

function loadModel(jsonFile) {
  var modelDefinition = require(jsonFile);
  return DataModel.extend(modelDefinition.name,
    modelDefinition.properties, {
      relations: modelDefinition.relations
    });
}

var UserPassportModel = loadModel('./models/user-passport.json');
var AuthProviderModel = loadModel('./models/auth-model.json');

exports.UserPassport = require('./models/user-passport')(UserPassportModel);
exports.AuthProvider = require('./models/auth-model')(AuthProviderModel);

exports.UserPassport.autoAttach = 'db';
exports.AuthProvider.autoAttach = null;

exports.PassportConfigurator = require('./passport-configurator');


