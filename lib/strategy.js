// Load modules.
var AWS = require('aws-sdk');
var util = require('util');
var passport = require('passport-strategy');
var CognitoSDK = require('amazon-cognito-identity-js-node');

AWS.CognitoIdentityServiceProvider.AuthenticationDetails = CognitoSDK.AuthenticationDetails;
AWS.CognitoIdentityServiceProvider.CognitoUserPool = CognitoSDK.CognitoUserPool;
AWS.CognitoIdentityServiceProvider.CognitoUser = CognitoSDK.CognitoUser;

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

  AWS.config.region = options.region;

  passport.Strategy.call(this);
  this.name = 'cognito';
  this._userPoolId = options.userPoolId;
  this._clientId = options.clientId;
  this._verify = verify;
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

  var user = {};
  var username = req.body.username;
  var password = req.body.password;

  if (!username || !password) {
    return this.fail({ message: 'Missing credentials' }, 400);
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
    onSuccess: function (session) {

      accessToken = session.getAccessToken().getJwtToken();
      idToken = session.getIdToken().getJwtToken();
      refreshToken = session.getRefreshToken().getToken();

      if (!accessToken || !idToken) {
        return self.fail({ message: options.badRequestMessage || 'Missing token' }, 400);
      }

      self._getUserAttributes(cognitoUser, function(profile) {
        profile.username = username;
        try {
          if (self._verify.length == 6) {
            self._verify(accessToken, idToken, refreshToken, profile, session, verified)
          } else { // length = 5
            self._verify(accessToken, idToken, refreshToken, profile, verified);
          }
        } catch (ex) {
          return self.error(ex);
        }
      })
    },
    onFailure: function(err) {
      // console.log(err);
      return self.fail(err);
    },
    mfaRequired: function(codeDeliveryDetails) {
      // MFA is required to complete user authentication. 
      // Get the code from user and call 
      // cognitoUser.sendMFACode(mfaCode, this)
      return self.fail({ message: options.badRequestMessage || 'Multi factor authentication Required' }, 424);
    },
    newPasswordRequired: function(userAttributes, requiredAttributes) {
      // User was signed up by an admin and must provide new 
      // password and required attributes, if any, to complete 
      // authentication.

      // userAttributes: object, which is the user's current profile. It will list all attributes that are associated with the user. 
      // Required attributes according to schema, which don’t have any values yet, will have blank values.
      // requiredAttributes: list of attributes that must be set by the user along with new password to complete the sign-in.

      var newPassword = req.body.newpassword;
      if (newPassword) {
        var attributesData = [];
        requiredAttributes.map(function(att) {
          attributesData[att] = req.body[att];
        });

        console.log("newPasswordRequired2 ", attributesData, requiredAttributes);
        //Try to validate user
        return cognitoUser.completeNewPasswordChallenge(newPassword, attributesData, this);
      } else {
        return self.fail({ message: options.badRequestMessage || 'New Password Required' }, 412);
      }
    }
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

  var self = this;
  cognitoUser.getUserAttributes(function(err, result) {
    if (err) return self.fail(err);

    var user = {}
    result.forEach(function(attr) {
      var obj = attr.getName();
      if(typeof(obj.Name) == "string"){
        user[obj.Name] = obj.Value;
      } else {
        // when using passport-cognito with 'amazon-cognito-identity-js'
        // an error occurs, this is a quick fix for this
        user[attr.getName()] = attr.getValue();
      }
    })
    callback(user);
  });
};


// Expose constructor.
module.exports = CognitoStrategy;
