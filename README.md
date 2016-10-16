# passport-cognito

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
    User.findOrCreate(..., function (err, user) {
      cb(err, user);
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
```
app.post('/auth/cognito',
  passport.authenticate('cognito', {
    successRedirect: '/',
    failureRedirect: '/login'
}));
```
