# www-authenticate [![Build Status](https://secure.travis-ci.org/randymized/www-authenticate.png?branch=master)](http://travis-ci.org/randymized/www-authenticate)

## Documentation
Provides the functionality needed for a client to use HTTP Basic or Digest authentication.  Also provides primitives for parsing WWW-Authenticate and Authentication_Info headers.

Parses the content of a WWW-Authenticate header sent by a server. Interpret the authentication challenge posed. Then generate the credentials for Authorization headers for subsequent requests from the server.

- Supports Basic and Digest authentication schemes.
- Supports 'auth' quality of protection (qop) and challenges that do not include qop.
- Supports MD5 and MD5-sess algorithms.
- Assumes Node.js, but otherwise makes no assumtion about framework.

## Limitations
- Basic authetication scheme is untested.
- Included tests only test Digest scheme against the rfc2617 example.
- Most of the permutations of qop and algorithm have not been tested.
- Little real-world testing.  That's where you can help!  Report any failures or submit a patch that resolves an authentication failure.
- Will not parse WWW-Authenticate headers that contain more than one challenge.  Please send an example of one if you find one in the field or modify the parser to parse it.
- Does not support auth-int qop, but will use auth qop if server allows either.  Support could surely be added in the future.
- Response to challenges without qop have not been tested.

## Getting Started
Install the module with: `npm install www-authenticate`
See examples below.

## Examples
Use the high level interface:
```javascript
var www_authenticate = require('www-authenticate');
var on_www_authenticate= www_authenticate(username,password)
var authenticator= on_www_authenticate.authenticator;

// Whenever you receive a response, send it to the authenticator.
// The authenticator will parse and record any challenge it contains.
authenticator.get_challenge(response);

//... now, whenever you make a request the authenticator will add an
// authorization header if a challenge has been received...
 var options= {
   method: "GET",
   path: "/dir/index.html"
 }
 authenticator.authenticate_request_options(options);
 if (authenticator.err) throw err;  // or do something similarly drastic
 http.request(options);
```
---
Use the low level interface:
```javascript
var www_authenticate = require('www-authenticate');
var on_www_authenticate= www_authenticate(username,password);

// now wait for HTTP/1.1 401 Unauthorized and then parse the WWW_Authenticate header
var authenticator= on_www_authenticate(response.headers['www-authenticate']);
if (authenticator.err) throw err; // or do something similarly drastic

//... now, whenever you make a request, add an Authorization header:
response.setHeader('authorization', authenticator.authorize('GET',url));
```
---
Parse www-authenticate or authentication-info headers:
```javascript
var parsers = require('www-authenticate').parsers;
var parsed= new parsers.WWW_Authenticate(request.headers['www-authenticate']);
console.log(parsed.scheme);
console.log(parsed.parms.nonce);

var parsed= new parsers.Authentication_Info(request.headers['authentication-info']);
console.log(parsed.parms.nonce);
```

## Contributing
In lieu of a formal styleguide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code using [Grunt](http://gruntjs.com/).

## Release History
_(Nothing yet)_

## License
Copyright (c) 2013 Randy McLaughlin
Licensed under the MIT license.
