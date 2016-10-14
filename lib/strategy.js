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

  options = options || {};

  var user = {}
  //  var username = req.body.username;
  //  var password = req.body.password;
  var username = 'miki@presen.to';
  var password = 'hayashi123';

  var authenticationData = {
    Username: username,
    Password: password
  };

  var authenticationDetails = new AWS.CognitoIdentityServiceProvider.AuthenticationDetails(authenticationData);
  var poolData = { 
    UserPoolId : 'ap-northeast-1_OfSjgoECq',
    ClientId : '45injqv7clgn1ld8g4eurtuouh'
  };

  var userPool = new AWS.CognitoIdentityServiceProvider.CognitoUserPool(poolData);
  var userData = {
    Username : username,
    Pool : userPool
  };

  var cognitoUser = new AWS.CognitoIdentityServiceProvider.CognitoUser(userData);
  cognitoUser.authenticateUser(authenticationDetails, {
    onSuccess: function (result) {
      console.log(result);
    },
    onFailure: function(err) {
      console.log(err);
    },
  });





};












