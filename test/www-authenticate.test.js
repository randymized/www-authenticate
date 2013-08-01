
'use strict';
require('should');
var www_authenticate = require('..');

var CNONCE='0a4f113b'

describe( 'www-authenticate', function() {
  describe( 'www_authenticate()', function() {
    it( 'should be a function', function() {
      www_authenticate.should.be.a( 'function' );
    } );
    it( 'should return a function', function() {
      www_authenticate()
    } );
    it( 'should authenticate rfc2617 example', function(done) {
      var header_parser= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      header_parser('Digest '+
                 'realm="testrealm@host.com", '+
                 'qop="auth,auth-int", '+
                 'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
                 'opaque="5ccc069c403ebaf9f0171e9517f40e41"',
        function(err,authorizer) {
          if (err) throw err;
          var authorize= authorizer.authorize; //function to produce Authorization header
          // now, whenever you need to create an Authorization header:
          authorize("GET","/dir/index.html").should.equal(
                'Digest username="Mufasa", '+
                'realm="testrealm@host.com", '+
                'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
                'uri="/dir/index.html", '+
                'qop=auth, '+
                'nc=00000001, '+
                'cnonce="'+CNONCE+'", '+
                'response="6629fae49393a05397450978507c4ef1", '+
                'opaque="5ccc069c403ebaf9f0171e9517f40e41"'
          );
          done();
        }
      );
    } );
    it( 'should increment nonce-count', function(done) {
      var header_parser= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      header_parser('Digest '+
                 'realm="testrealm@host.com", '+
                 'qop="auth,auth-int", '+
                 'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
                 'opaque="5ccc069c403ebaf9f0171e9517f40e41"',
        function(err,authorizer) {
          if (err) throw err;
          var authorize= authorizer.authorize;
          authorize("GET","/dir/index.html");
          authorize("GET","/dir/index.html").should.include('nc=00000002');
          done();
        }
      );
    } );
  } );
} );
