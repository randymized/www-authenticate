
'use strict';
should= require('should');
var www_authenticate = require('..')
  , parsers = www_authenticate.parsers;
  ;

var CNONCE='0a4f113b'
var RFC2617_challenge= 'Digest '+
                 'realm="testrealm@host.com", '+
                 'qop="auth,auth-int", '+
                 'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
                 'opaque="5ccc069c403ebaf9f0171e9517f40e41"';
var RFC2617_response=
    'Digest username="Mufasa", '+
    'realm="testrealm@host.com", '+
    'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
    'uri="/dir/index.html", '+
    'qop=auth, '+
    'nc=00000001, '+
    'cnonce="'+CNONCE+'", '+
    'response="6629fae49393a05397450978507c4ef1", '+
    'opaque="5ccc069c403ebaf9f0171e9517f40e41"';

var mufasa_credentials= www_authenticate.user_credentials("Mufasa","Circle Of Life");

function replace_nc(replacement,s)
{
  return s.replace('00000001',replacement)
}
function replace_response(replacement,s)
{
  return s.replace('6629fae49393a05397450978507c4ef1',replacement)
}
function replace_uri(replacement,s)
{
  return s.replace('/dir/index.html',replacement)
}
function replace_cnonce(replacement,s)
{
  return s.replace(CNONCE,replacement)
}

describe( 'www-authenticate', function() {
  describe( 'www_authenticate()', function() {
    it( 'should be a function', function() {
      www_authenticate.should.be.a( 'function' );
    } );
    it( 'should return a function', function() {
      www_authenticate('user')
    } );
    it( 'should authenticate rfc1945 example', function(done) {
      var on_www_authenticate= www_authenticate("Aladdin","open sesame")
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate('Basic realm="sample"');
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize("GET","/dir/index.html").should.equal(
            'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='
      );
      done();
    } );
    it( 'should authenticate rfc1945 example even without method and path (they do not matter)', function(done) {
      var on_www_authenticate= www_authenticate("Aladdin","open sesame")
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate('Basic realm="sample"');
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize().should.equal(
            'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=='
      );
      done();
    } );
    it( 'should be capable of doing Basic authentication without any password', function(done) {
      var on_www_authenticate= www_authenticate("Aladdin")
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate('Basic realm="sample"');
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize().should.equal(
            'Basic ' + new Buffer('Aladdin').toString('base64')
      );
      done();
    } );
    it( 'should handle a blank password differently than a non-existant one', function(done) {
      var on_www_authenticate= www_authenticate("Aladdin", "")
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate('Basic realm="sample"');
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize().should.equal(
            'Basic ' + new Buffer('Aladdin:').toString('base64')
      );
      done();
    } );
    it( 'should authenticate rfc2617 example', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate(RFC2617_challenge);
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize("GET","/dir/index.html").should.equal(RFC2617_response);
      done();
    } );
    it( 'should allow a blank cnonce to be specified', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:''})
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate(RFC2617_challenge)
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize("GET","/dir/index.html").should.equal(
        replace_cnonce('',
          replace_response('feee16a35faef0a0371c7210e4bdb6a5',RFC2617_response)
        )
      );
      done();
    } );
    it( 'should generate a hexadecimal cnonce if one is not specified', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life")
      //...receive HTTP/1.1 401 Unauthorized
      // parse header['www-authenticate']:
      var authenticator= on_www_authenticate(RFC2617_challenge)
      if (authenticator.err) throw err;
      // now, whenever you need to create an Authorization header:
      authenticator.authorize("GET","/dir/index.html").search(/cnonce="[0-9a-f]+"/).should.not.equal('-1');
      done();
    } );
    it( 'should increment nonce-count', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      var authenticator= on_www_authenticate(RFC2617_challenge);
      authenticator.authorize("GET","/dir/index.html");
      authenticator.authorize("GET","/dir/index.html").should.include('nc=00000002');
      done();
    } );
    it( 'should parse an Authentication_Info header', function(done) {
      var parsed= new parsers.Authentication_Info(
                 'nextnonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
                 'qop="auth,auth-int", '+
                 'rspauth="6629fae49393a05397450978507c4ef1", '+
                 'nc=00000001, '+
                 'cnonce="abc""def"'
              );
      parsed.should.not.have.property('err');
      var parms= parsed.parms;
      parms.should.have.property('nextnonce','dcd98b7102dd2f0e8b11d0f600bfb0c093');
      parms['nextnonce'].should.equal('dcd98b7102dd2f0e8b11d0f600bfb0c093');
      parms['qop'].should.equal('auth,auth-int');
      parms['rspauth'].should.equal('6629fae49393a05397450978507c4ef1');
      parms['nc'].should.equal('00000001');
      parms['cnonce'].should.equal('abc"def');  // double double quote properly parsed as single double quote
      done();
    } );
    it( 'should correctly parse a quoted string that includes a comma', function(done) {
      var parsed= new parsers.Authentication_Info(
                 'nextnonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", '+
                 'qop="auth,auth-int", '+
                 'rspauth="6629fae49393a05397450978507c4ef1", '+
                 'nc=00000001, '+
                 'cnonce="abc""d,ef"'
              );
      parsed.should.not.have.property('err');
      var parms= parsed.parms;
      parms.should.have.property('nextnonce','dcd98b7102dd2f0e8b11d0f600bfb0c093');
      parms['nextnonce'].should.equal('dcd98b7102dd2f0e8b11d0f600bfb0c093');
      parms['qop'].should.equal('auth,auth-int');
      parms['rspauth'].should.equal('6629fae49393a05397450978507c4ef1');
      parms['nc'].should.equal('00000001');
      parms['cnonce'].should.equal('abc"d,ef');  // double double quote properly parsed as single double quote
      done();
    } );
    it( 'should provide the old,deprecated higher-level authenticator', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      var authenticator= on_www_authenticate.authenticator;
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      var headers= {}
      authenticator.authenticate_headers(headers,"GET","/dir/index.html");
      if (authenticator.err) throw err;
      headers.should.have.property('authorization',RFC2617_response);
      done();
    } );
    it( 'should authenticate multiple messages with the old,deprecated higher-level authenticator', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      var authenticator= on_www_authenticate.authenticator;
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      var headers= {}
      authenticator.authenticate_headers(headers,"GET","/dir/index.html");
      if (authenticator.err) throw err;
      headers.should.have.property('authorization',RFC2617_response);

      headers= {}
      authenticator.authenticate_headers(headers,"GET","/dir/other.html");
      if (authenticator.err) throw err;
      headers.should.have.property('authorization',
        replace_uri('/dir/other.html',
          replace_nc('00000002',
            replace_response('8fd933ee1915789a949cf71f0cee4581',RFC2617_response)
          )
        )
      );
      done();
    } );
    it( 'can authenticate using the old,deprecated higher-level interface and the options object to http.request', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      var authenticator= on_www_authenticate.authenticator;
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      var options= {
        method: "GET",
        path: "/dir/index.html"
      }
      authenticator.authenticate_request_options(options);
      if (authenticator.err) throw err;
      options.should.have.property('headers');
      options.headers.should.have.property('authorization',RFC2617_response);
      done();
    } );
    it( 'can simply return the authentication string from the the old,deprecated higher level functionality', function(done) {
      var on_www_authenticate= www_authenticate("Mufasa","Circle Of Life",{cnonce:CNONCE})
      var authenticator= on_www_authenticate.authenticator;
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      if (authenticator.err) throw err;
      authenticator.authentication_string("GET","/dir/index.html").should.equal(RFC2617_response);
      done();
    } );
    it( 'allows user credentials instead of username/password ', function(done) {
      var credentials= mufasa_credentials;
      var on_www_authenticate= www_authenticate(credentials,{cnonce:CNONCE})
      var authenticator= on_www_authenticate.authenticator;
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      if (authenticator.err) throw err;
      authenticator.authentication_string("GET","/dir/index.html").should.equal(RFC2617_response);
      done();
    } );
    it( 'exports user credentials that produce a hash of username and password for basic authentication ', function(done) {
      var credentials= www_authenticate.user_credentials("Aladdin","open sesame");
      credentials.basic().should.equal('QWxhZGRpbjpvcGVuIHNlc2FtZQ==');
      done();
    } );
    it( 'exports user credentials that produce a hash of username, password and realm for digest authentication ', function(done) {
      var credentials= mufasa_credentials;
      credentials.digest('testrealm@host.com').should.equal('939e7578ed9e3c518a452acee763bce9');
      done();
    } );
    it( 'exports a user credentials object that allows accessing the username', function(done) {
      var credentials= mufasa_credentials;
      credentials.username.should.equal('Mufasa');
      done();
    } );
    it( 'exports a user credentials object that hides the password', function(done) {
      var credentials= mufasa_credentials;
      credentials.should.not.have.property('password');
      done();
    } );

    it( 'should provide a higher-level authenticator', function(done) {
      var authenticator= www_authenticate.authenticator("Mufasa","Circle Of Life",{cnonce:CNONCE})
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      var headers= {}
      authenticator.authenticate_headers(headers,"GET","/dir/index.html");
      if (authenticator.err) throw err;
      headers.should.have.property('authorization',RFC2617_response);
      done();
    } );
    it( 'should authenticate multiple messages with the higher-level authenticator', function(done) {
      var authenticator= www_authenticate.authenticator(mufasa_credentials,{cnonce:CNONCE})
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      var headers= {}
      authenticator.authenticate_headers(headers,"GET","/dir/index.html");
      if (authenticator.err) throw err;
      headers.should.have.property('authorization',RFC2617_response);

      headers= {}
      authenticator.authenticate_headers(headers,"GET","/dir/other.html");
      if (authenticator.err) throw err;
      headers.should.have.property('authorization',
        replace_uri('/dir/other.html',
          replace_nc('00000002',
            replace_response('8fd933ee1915789a949cf71f0cee4581',RFC2617_response)
          )
        )
      );
      done();
    } );
    it( 'can authenticate using the options object to http.request', function(done) {
      var authenticator= www_authenticate.authenticator(mufasa_credentials,{cnonce:CNONCE})
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      var options= {
        method: "GET",
        path: "/dir/index.html"
      }
      authenticator.authenticate_request_options(options);
      if (authenticator.err) throw err;
      options.should.have.property('headers');
      options.headers.should.have.property('authorization',RFC2617_response);
      done();
    } );
    it( 'can simply return the authentication string from the higher level functionality', function(done) {
      var authenticator= www_authenticate.authenticator(mufasa_credentials,{cnonce:CNONCE})
      authenticator.get_challenge({
        statusCode: 401,
        headers: {
          'www-authenticate': RFC2617_challenge
        }
      });
      if (authenticator.err) throw err;
      authenticator.authentication_string("GET","/dir/index.html").should.equal(RFC2617_response);
      done();
    } );
  } );
} );
