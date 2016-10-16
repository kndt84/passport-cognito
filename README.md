# passport-cognito

[Passport](http://passportjs.org/) strategy for with Cognito User Pools not for Cognito Identity.

This module lets you authenticate using Cognito User Pools in your Node.js applications.
By plugging into Passport, Cognito User Pools authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install
```sh
$ npm install passport-facebook
```    

## Usage

### Confiture Strategy

```javascript
var CognitoStrategy = require('passport-cognito')

passport.use(new CognitoStrategy({
    userPoolId: 'ap-northeast-1_eSjqLfqKc',
    clientId: 'vtvg02tr21zmxvspyvawtv09b',
    region: 'ap-northeast-1'
  },
  function(accessToken, refreshToken, profile, cb) {
    process.nextTick(function() {
      ...
      cb(null, user);
    });
  }
));
```

### Authenticate Requests
To authenticate a user, send username and password by POST request like the following.

```javascript 
$.ajax({
  type: "POST",
  url: '/auth/cognito',
  data: { username: username, password: password }
})
```
Then the strategy receive username and password as a req object. In detail, req.body.username and req.body.password should not be undefined. Then, call authenticate method as express middleware.
```javascript
app.post('/auth/cognito',
  passport.authenticate('cognito', {
    successRedirect: '/',
    failureRedirect: '/login'
}));
```
