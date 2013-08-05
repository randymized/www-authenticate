
/*
 * www-authenticate
 * https://github.com/randymized/www-authenticate
 *
 * Copyright (c) 2013 Randy McLaughlin
 * Licensed under the MIT license.
 */

'use strict';

var crypto= require('crypto')
  , md5sum = crypto.createHash('md5')
  , parsers= require('./parsers')
  ;

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function hex8(num)
{
  return ("00000000" + num.toString(16)).slice(-8);
}

module.exports = function(username,password,options)
{
  var cnonce, password_optional;
  if (options) {
    if (toString.call(options.cnonce) == '[object String]')
      cnonce= options.cnonce;
    password_optional= options.password_optional
  }
  if (cnonce === void 0) cnonce= crypto.pseudoRandomBytes(8).toString('hex');
  return function parse_header(www_authenticate)
  {
    function Authenticator()
    {
      function note_error(err)
      {
        this.err= err
      }
      var nc= 0;

      var parsed= new parsers.WWW_Authenticate(www_authenticate);
      if (parsed.err) return note_error(parsed.err);
      var auth_parms= this.parms= parsed.parms;
      this.cnonce= cnonce;

      switch(parsed.scheme) {
        case 'Basic':
          var auth_string=
            password !== '' && !password && password_optional?
              'Basic '+new Buffer(username, "ascii").toString("base64")
            :
              'Basic '+new Buffer(username+':'+password, "ascii").toString("base64")
          this.authorize= function() {
            return auth_string;
          };
          return;
        case 'Digest':
          var realm= auth_parms.realm;
          if (!realm) {
            return note_error("Realm not found in www-authenticate header.");
          }

          var ha1=
            password !== '' && !password && password_optional?
              md5(username+':'+realm)
              :
              md5(username+':'+realm+':'+password)
          var nonce= auth_parms.nonce;
          if (!nonce) {
            return note_error("Nonce not found in www-authenticate header.");
          }

          var fixed= 'Digest username="'+username+'",'+
              ' realm="'+realm+'",'+
              ' nonce="'+nonce+'",';
          var qop= auth_parms.qop;
          if (!qop) {
              this.authorize= function(method,digestURI) {
                var ha2= md5(method+':'+digestURI);
                return fixed+
                  ' uri="'+digestURI+'",'+
                  ' response="'+md5(ha1+':'+nonce+':'+ha2)+'",';
              };
              return;
          }
          else {
            var qopa= qop.split(',');
            var q, x, _i, _len;
            for (_i = 0, _len = qopa.length; _i < _len; _i++) {
              if ('auth' === qopa[_i]) {
                var opaque= auth_parms.opaque;
                var algorithm= auth_parms.algorithm;
                if (algorithm) {
                  fixed+= ' algorithm="'+algorithm+'",';
                }
                else {
                  algorithm= 'MD5';
                }
                var a1= 'MD5-sess' == algorithm ?
                  md5(ha1+':'+nonce+':'+cnonce)
                  :
                  ha1;
                this.authorize= function(method,digestURI) {
                  var ha2= md5(method+':'+digestURI);
                  nc= nc+1;
                  var hexed_nc= hex8(nc);
                  var s= fixed+
                    ' uri="'+digestURI+'",'+
                    ' qop=auth,'+
                    ' nc='+hexed_nc+','+
                    ' cnonce="'+cnonce+'",'+
                    ' response="'+md5(a1+':'+nonce+':'+hexed_nc+':'+cnonce+':auth:'+ha2)+'"';
                  if (opaque) {
                    s+= ', opaque="'+opaque+'"';
                  }
                  return s;
                };
                return;
              }
              return note_error('Server does not accept any supported quality of protection techniques.');
            }
          }
          break;
        default:
          return note_error("Unknown scheme");
      }
    }

    return new Authenticator();
  };
};

module.exports.parsers= parsers;