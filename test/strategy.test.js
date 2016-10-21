/* global describe, it, expect, before */
/* jshint expr: true */
var chai = require('chai');
var CognitoStrategy = require('../lib/strategy');


describe('Strategy', function() {
    
  describe('constructed', function() {
    var strategy = new CognitoStrategy({
        userPoolId: 'ap-northeast-1_asdfaga',
        clientId: '123asjdfasdfafdad',
        region: 'ap-northeast-1'        
      },
      function() {});
    
    it('should be named cognito', function() {
      expect(strategy.name).to.equal('cognito');
    });
  })

  describe('constructed with undefined options', function() {
    it('should throw', function() {
      expect(function() {
        var strategy = new CognitoStrategy(undefined, function(){});
      }).to.throw(Error);
    });
  })

  describe('constructed without a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        var strategy = new CognitoStrategy({});
      }).to.throw(Error);
    });
  })

  describe('authorization request without username or password', function() {
    var strategy = new CognitoStrategy({
        userPoolId: 'ap-northeast-1_asdfaga',
        clientId: '123asjdfasdfafdad',
        region: 'ap-northeast-1'  
      }, function() {});
    
    var err;
    var code;

    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(e, c){
          err = e;
          code  = c;
          done();
        })
        .req(function(req) {
          req.body = {}
        })
        .authenticate();
    });

    it('should be fail', function() {
      expect(err.message).to.equal('Missing credentials');
      expect(code).to.equal(400);
    });
  });

  describe('authorization request with username and password', function() {
    var strategy = new CognitoStrategy({
        userPoolId: 'ap-northeast-1_asdfaga',
        clientId: '123asjdfasdfafdad',
        region: 'ap-northeast-1'  
      }, function() {});
    
    var err;
    var code;

    before(function(done) {
      chai.passport.use(strategy)
        .fail(function(e, c){
          err = e;
          done();
        })
        .req(function(req) {
          req.body = {}
          req.body.username = "username"
          req.body.password = "password"
        })
        .authenticate();
    });

    it('should be fail as resource not found', function() {
      expect(err.message).to.equal('User pool client 123asjdfasdfafdad does not exist.');
      expect(err.statusCode).to.equal(400);
    });
  });

})



