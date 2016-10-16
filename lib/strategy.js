// Load modules.
var AWS = require('aws-sdk');
var util = require('util');
var Strategy = require('passport-strategy').Strategy;

var AuthenticationDetails = require('./cognito/AuthenticationDetails');
var CognitoUserPool = require('./cognito/CognitoUserPool');
var CognitoUser = require('./cognito/CognitoUser');

AWS.CognitoIdentityServiceProvider.AuthenticationDetails = AuthenticationDetails;
AWS.CognitoIdentityServiceProvider.CognitoUserPool = CognitoUserPool;
AWS.CognitoIdentityServiceProvider.CognitoUser = CognitoUser;

/**
 * `Strategy` constructor.
 *
 * The Facebook authentication strategy authenticates requests by delegating to
 * Facebook using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `userPoolID`     Cognito User Pool ID        // required
 *   - `clientID`       Cognito app client ID       // required
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
  if (!verify) throw new Error('Cognito strategy requires a verify function');

  AWS.config.region = 'ap-northeast-1';

  Strategy.call(this);
  this.name = 'cognito';
  this._userPoolId = options.userPoolId;
  this._clientId = options.clientId;
  this._verify = verify;
}


// Inherit from `passport-strategy`.
util.inherits(CognitoStrategy, Strategy);


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

      accessToken = result.getAccessToken().getJwtToken();
      idToken = result.getIdToken().getJwtToken();
      refreshToken = result.getRefreshToken().getToken();

      if (!accessToken || !idToken) {
        return self.fail({ message: options.badRequestMessage || 'Missing idToken' }, 400);
      }

      self._getUserAttributes(cognitoUser, (user) => {
        try {
          self._verify(accessToken, idToken, refreshToken, user, verified);
        } catch (ex) {
          return self.error(ex);
        }
      })
    },
    onFailure: function(err) {
      console.log(err);
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
  cognitoUser.getUserAttributes(function(err, result) {
    if (err) {
        alert(err);
        return;
    }

    var user = {}
    result.forEach((attr) => {
      var obj = attr.getName();
      user[obj.Name] = obj.Value;
    })
    callback(user);
  });
};


// Expose constructor.
module.exports = CognitoStrategy;
