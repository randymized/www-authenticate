
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

module.exports = function(username,password,options)
{
  var cnonce;
  if (options) {
    if (options.cnonce)
      cnonce= options.cnonce;
  }
  if (!cnonce) cnonce= crypto.pseudoRandomBytes(8);
  return function parse_header(www_authenticate,receiver)
  {
    var authorize, nc= 0;

    // This is a very crude parser that will fail if more than one challenge
    // and may not work with some odd combinations of parameters.
    var auth_parms= {};
    var scheme;

    function respond_with(authorize_fn)
    {
      receiver(null, {authorize:authorize_fn, auth_parms:auth_parms,cnonce:cnonce});
    }
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
        rest= m && m[1];
      }
    }
    parse();

    if ('Basic' == scheme) {
      var auth_string= 'Basic '+new Buffer(username+':'+password, 'base64').toString('ascii');
      return respond_with(function() {
        return auth_string;
      });
    }
    else if ('Digest' == scheme) {
      var realm= auth_parms.realm;
      if (!realm) {
        return receiver("Realm not found in www-authenticate header.");
      }

      var ha1= md5(username+':'+realm+':'+password);
      var nonce= auth_parms.nonce;
      if (!nonce) {
        return receiver("Nonce not found in www-authenticate header.");
      }

      var fixed= 'Digest username="'+username+'",'+
          ' realm="'+realm+'",'+
          ' nonce="'+nonce+'",';
      var qop= auth_parms.qop;
      if (!qop) {
          return respond_with(function(method,digestURI) {
            var ha2= md5(method+':'+digestURI);
            return fixed+
              ' uri="'+digestURI+'",'+
              ' response="'+md5(ha1+':'+nonce+':'+ha2)+'",';
          });
      }
      else {
        var qopa= qop.split(',');
        var q, x, _i, _len;
        for (_i = 0, _len = qopa.length; _i < _len; _i++) {
          if ('auth' === qopa[_i]) {
            var opaque= auth_parms.opaque;
            var algorithm= auth_parms.algorithm;
            if (algorithm) {
              fixed+= ', algorithm="'+algorithm+'"';
            }
            else {
              algorithm= 'MD5';
            }
            var a1= 'MD5-sess' == algorithm ?
              md5(ha1+':'+nonce+':'+cnonce)
              :
              ha1;
            return respond_with(function(method,digestURI) {
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
            });
          }
          return receiver('Server does not accept any supported quality of protection techniques.');
        }
      }
    }
    else return receiver("Unknown scheme");

    receiver("Failed to come up with an authentication scheme.");
  };
};
