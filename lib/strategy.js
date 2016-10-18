// Load modules.
var AWS = require('aws-sdk');
var util = require('util');
var passport = require('passport-strategy');

var AuthenticationDetails = require('./cognito/AuthenticationDetails');
var CognitoUserPool = require('./cognito/CognitoUserPool');
var CognitoUser = require('./cognito/CognitoUser');

AWS.CognitoIdentityServiceProvider.AuthenticationDetails = AuthenticationDetails;
AWS.CognitoIdentityServiceProvider.CognitoUserPool = CognitoUserPool;
AWS.CognitoIdentityServiceProvider.CognitoUser = CognitoUser;

/**
 * `Strategy` constructor.
 *
 * The Cognito User Pools authentication strategy.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`, `idToken`
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `userPoolId`     Cognito User Pool Id        // required
 *   - `clientId`       Cognito app client Id       // required
 *   - `region`         AWS region                  // required
 *
 * Examples:
 *
 *     passport.use(new CognitoStrategy({
 *         userPoolId: 'ap-northeast-1_eSjqLfqKc',
 *         clientId: 'vtvg02tr21zmxvspyvawtv09b',
 *         region: 'ap-northeast-1'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function CognitoStrategy(options, verify) {

  if (!options) throw new Error('Cognito strategy requires options');
  if (!verify) throw new Error('Cognito strategy requires a verify callback');

  AWS.config.region = 'ap-northeast-1';

  passport.Strategy.call(this);
  this.name = 'cognito';
  this._userPoolId = options.userPoolId;
  this._clientId = options.clientId;
  this._verify = verify;
  this.accessToken;
  this.idToken;
  this.refreshToken;
}


// Inherit from `passport-strategy`.
util.inherits(CognitoStrategy, passport.Strategy);


/**
 * Authenticate request
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
CognitoStrategy.prototype.authenticate = function(req, options) {

  var options = options || {};
  var user = {};
  var username = req.body.username;
  var password = req.body.password;

  if (!username || !password) {
    return this.fail({ message: options.badRequestMessage || 'Missing credentials' }, 400);
  }

  var authenticationDetails = this._createAuthenticationDetails(username, password);
  var cognitoUser = this._createCognitoUser(username);

  var self = this;

  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: function (result) {

      self.accessToken = result.getAccessToken().getJwtToken();
      self.idToken = result.getIdToken().getJwtToken();
      self.refreshToken = result.getRefreshToken().getToken();

      if (!accessToken || !idToken) {
        return self.fail({ message: options.badRequestMessage || 'Missing token' }, 400);
      }

      self._getUserAttributes(cognitoUser, function(profile) {
        try {
          self._verify(self.accessToken, self.idToken, self.refreshToken, profile, verified);
        } catch (ex) {
          return self.error(ex);
        }
      })
    },
    onFailure: function(err) {
      console.log(err);
      return self.fail(err);
    },
  });

};


/**
 * Create authentication detail object
 *
 * @param {string} username
 * @param {string} password
 * @return {AuthenticationDetails}
 * @access protected
 */
CognitoStrategy.prototype._createAuthenticationDetails = function(username, password) {
  var authenticationData = {
    Username: username,
    Password: password
  };

  return new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData);
};


/**
 * Create cognito user object
 *
 * @param {string} username
 * @return {CognitoUser}
 * @access protected
 */
CognitoStrategy.prototype._createCognitoUser = function(username) {
  var poolData = { 
    UserPoolId : this._userPoolId,
    ClientId : this._clientId
  };
  var userPool = new AWS.CognitoIdentityServiceProvider.CognitoUserPool(poolData);
  var userData = {
    Username : username,
    Pool : userPool
  };

  return new AWS.CognitoIdentityServiceProvider.CognitoUser(userData);
};


/**
 * Get user attributes as a object
 *
 * @param {CognitoUser} cognitoUser
 * @param {function} callback
 * @return {object}
 * @access protected
 */
CognitoStrategy.prototype._getUserAttributes = function(cognitoUser, callback) {
  self = this;
  cognitoUser.getUserAttributes(function(err, result) {
    if (err) return self.fail(err);

    var user = {}
    result.forEach(function(attr) {
      var obj = attr.getName();
      user[obj.Name] = obj.Value;
    })
    callback(user);
  });
};


// Expose constructor.
module.exports = CognitoStrategy;
