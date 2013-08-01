
'use strict';
require('should');
var www_authenticate = require( '../lib/www-authenticate.js' );

describe( 'www-authenticate', function() {
  describe( 'www_authenticate()', function() {
    it( 'should be a function', function() {
      www_authenticate.should.be.a( 'function' );
    } );
    it( 'should return a function', function() {
      www_authenticate().should.be.a( 'function' );
    } );
  } );
} );
