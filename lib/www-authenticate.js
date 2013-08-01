
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
  , ParseAuth= /(\w+)\s+(.*)/  // -> scheme, params
  , GetName= / *([#$%&'+-.<>_`|0-9a-zA-Z]+)=(.*)/
  , GetToken= /([#$%&'+-.<>_`|0-9a-zA-Z]+)(.*)/
  , GetQuoted= /"([^"]*)"(.*)/
  , DropComma= /\s?,\s(.*)/
  ;

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}
function hex8(num)
{
  return ("00000000" + num.toString(16)).slice(-8);
}
module.exports = function(username,password)
{
  return function parse_header(www_authenticate,receiver)
  {
    var authorize, nc= 0;

    // This is a very crude parser that will fail if more than one challenge
    // and may not work with some odd combinations of parameters.
    var auth_parms= {};
    var ha1, fixed;
    var scheme;

    function parse()
    {
      var m= www_authenticate.match(ParseAuth);
      scheme= m[1];
      var rest= m[2];
      while (rest) {
        m= rest.match(GetName);
        var value;
        var token= m[1];
        rest= m[2];
        if ('"' == rest.charAt(0)) {
          value= '';
          while ('"' == rest.charAt(0)) {
            m= rest.match(GetQuoted);
            value+= m[1]
            rest= m[2]
          }
        }
        else {
          m= params.match(GetToken);
          value= m[1];
          rest= m[2];
        }
        auth_parms[token]= value;
        m= rest.match(DropComma);
        rest= m[1];
      }
    }
    parse();

    if ('Basic' == scheme) {
      fixed= 'Basic '+new Buffer(username+':'+password, 'base64').toString('ascii');
      authorize= function() {
        return fixed;
      }
    }
    else if ('Digest' == scheme) {
      var realm= auth_parms.realm;
      if (!realm) {
        return receiver("Realm not found in www-authenticate header.");
      }

      var nonce= auth_parms.nonce;
      if (!nonce) {
        return receiver("Nonce not found in www-authenticate header.");
      }

      fixed= 'Digest username="'+username+'",'+
          ' realm="'+realm+'",'+
          ' nonce="'+nonce+'",';
      cnonce= crypto.randomBytes(32, function(ex, buf) {
        var token = buf.toString('hex');
      });
      var qop= auth_parms.qop;
      if (!qop) {
        ha1= md5(username+':'+realm+':'+password);
        authorize= function(method,digestURI) {
          var ha2= md5(method+':'+digestURI);
          return fixed+
            ' uri="'+digestURI+'",'+
            ' response="'+md5(ha1+':'+nonce+':'+ha2)+'",';
        }
      }
      else {
        var qopa= qop.split(',');
        var q, x, _i, _len;
        for (_i = 0, _len = qopa.length; _i < _len; _i++) {
          if ('auth' === qopa[_i]) {
            var opaque= auth_parms.opaque;
            ha1= md5(username+':'+realm+':'+password);
            var algorithm= auth_parms.algorithm;
            fixed= 'Digest username="'+username+'",'+
                ' realm="'+realm+'",'+
                ' nonce="'+nonce;
            if (algorithm) {
              fixed+= ', algorithm="'+algorithm+'"';
            }
            else {
              algorithm= 'MD5';
            }
            if ('auth' == qop) {
              if (!ha1) {
                ha1= md5(username+':'+realm+':'+password+':'+nonce);
              }
              if ('MD5-sess' == algorithm) {
                ha1= md5(ha1+':'+nonce+':'+cnonce);
              }
              authorize= function(method,digestURI) {
                var ha2= md5(method+':'+digestURI);
                nc= nc+1;
                var s= fixed+
                  ' uri="'+digestURI+'",'+
                  ' qop=auth,'+
                  ' nc='+hex8(nc)+','+
                  ' cnonce="'+cnonce+'",'+
                  ' response="'+md5(ha1+':'+nonce+':'+nc+':'+cnonce+':'+qop+':'+ha2)+'"';
                if (opaque) {
                  s+= ', opaque="'+opaque+'"';
                }
                return s;
              }
            }
          }
        }
        return receiver('Server does not accept any supported quality of protection techniques.');
      }
    }
    else return receiver("Unknown scheme");

    if (authorize) {
      receiver(null, {authorize:authorize, auth_parms:auth_parms});
    }
    else {
      receiver("Failed to come up with an authentication scheme.");
    }
  };
};
