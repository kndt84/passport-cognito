// Load modules.
var passport = require('passport-strategy');
var AWS = require('aws-sdk');
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
 *   - `email`          registered email            // optional
 *   - `phoneNumber`    registered phone number     // optional
 *   - `password`       password                    // required
 *   - `region`         AWS region                  // required
 *
 * Examples:
 *
 *     passport.use(new FacebookStrategy({
 *         userPoolId: '123-456-789',
 *         clientId: 'shhh-its-a-secret',
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
function Strategy(options, verify) {

  if (!options) throw new Error('Cognito strategy requires options');
  if (!verify) throw new Error('Cognito strategy requires a verify function');
//  AWS.config.region = options.region;
  AWS.config.region = 'ap-northeast-1';

  passport.Strategy.call(this);
  this.name = 'cognito';
  this._userPoolId = options.userPoolId;
  this._clientId = options.clientId;
  this._verify = verify;
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, passport.Strategy);


/**
 * Authenticate request
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
Strategy.prototype.authenticate = function(req, options) {

  var options = options || {};
  var sessionData;

  var user = {};
  var username = req.body.username;
  var password = req.body.password;

  var cognitoUser = this._getCognitoUser(username, password);

  this._authenticateUser(cognitoUser)
  .then(result => {
    accessToken = result.getAccessToken().getJwtToken();
    idToken = result.getIdToken().getJwtToken();
    refreshToken = result.getIdToken().getToken();

    if (!idToken) {
      return this.fail({ message: options.badRequestMessage || 'Missing idToken' }, 400);
    }

    var self = this;

    function verified(err, user, info) {
      if (err) { return self.error(err); }
      if (!user) { return self.fail(info); }
      self.success(user, info);
    }

    try {
      this._verify(accessToken, idToken, refreshToken, user, verified);
    } catch (ex) {
      return self.error(ex);
    }

  })
};


/**
 * Authenticate user
 *
 * @param {string} username
 * @param {string} password
 * @return {CognitoUserSession} password
 * @access protected
 */
Strategy.prototype._authenticateUser = function(cognitoUser) {

  return new Promise(resolve => {
    cognitoUser.authenticateUser(authenticationDetails, {
      onSuccess: function (result) {
        resolve(result);
      },
      onFailure: function(err) {
        console.log(err);
      },
    });
  })
};


/**
 * Authenticate user
 *
 * @param {CognitoUser} cognitoUser
 * @return {CognitoUserSession} password
 * @access protected
 */
Strategy.prototype._getUserAttributes = function(cognitoUser) {

  return new Promise(resolve => {
    cognitoUser.getUserAttributes(function(err, result) {
      if (err) {
          alert(err);
          return;
      }
      resolve(result);
    });
  });
};


/**
 * Authenticate user
 *
 * @param {string} username
 * @param {string} password
 * @return {cognitoUser}
 * @access protected
 */
Strategy.prototype._getCognitoUser = function(username, password) {

  var authenticationData = {
    Username: username,
    Password: password
  };

  var authenticationDetails = new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData);
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
}

// Expose constructor.
module.exports = Strategy;
