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

})



