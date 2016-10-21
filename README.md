[![Build Status](https://travis-ci.org/kndt84/passport-cognito.svg?branch=master)](https://travis-ci.org/kndt84/passport-cognito)
[![Code Climate](https://codeclimate.com/github/kndt84/passport-cognito/badges/gpa.svg)](https://codeclimate.com/github/kndt84/passport-cognito)
[![dependencies Status](https://david-dm.org/kndt84/passport-cognito/status.svg)](https://david-dm.org/kndt84/passport-cognito)

# passport-cognito

[Passport](http://passportjs.org/) strategy for Cognito User Pools not for Cognito Identity.

This module lets you authenticate using Cognito User Pools in your Node.js applications.
By plugging into Passport, Cognito User Pools authentication can be easily and
unobtrusively integrated into any application or framework that supports
[Connect](http://www.senchalabs.org/connect/)-style middleware, including
[Express](http://expressjs.com/).

## Install
```sh
$ npm install passport-cognito
```    

## Usage

### Configure Strategy

```javascript
var CognitoStrategy = require('passport-cognito')

passport.use(new CognitoStrategy({
    userPoolId: 'ap-northeast-1_eSjqLfqKc',
    clientId: 'vtvg02tr21zmxvspyvawtv09b',
    region: 'ap-northeast-1'
  },
  function(accessToken, idToken, refreshToken, user, cb) {
    process.nextTick(function() {
      ...
      cb(null, user);
    });
  }
));
```

### Authenticate Requests
To authenticate a user, send username and password to serser-side by POST request like the following.

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
# FAQ

## How to get session expiration ?
You can get session object by adding a variable to argument vector. Then, by executing getExpiration method, session expiration is retrieved.

```javascript
var CognitoStrategy = require('passport-cognito')

passport.use(new CognitoStrategy({
    userPoolId: 'ap-northeast-1_eSjqLfqKc',
    clientId: 'vtvg02tr21zmxvspyvawtv09b',
    region: 'ap-northeast-1'
  },
  function(accessToken, idToken, refreshToken, user, session, cb) {
    process.nextTick(function() {
      user.expiration = session.getIdToken().getExpiration();
      ...
      cb(null, user);
    });
  }
));
```


