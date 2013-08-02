# www-authenticate [![Build Status](https://secure.travis-ci.org/randymized/www-authenticate.png?branch=master)](http://travis-ci.org/randymized/www-authenticate)

> Parse WWW-Authenticate header and generate Authorization request headers for HTTP Basic and Digest authentication clients.

## Getting Started
Install the module with: `npm install www-authenticate`

```javascript
var www_authenticate = require( 'www-authenticate' );
```

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

## Examples
var www_authenticate = require('www-authenticate');
var on_www_authenticate= www_authenticate(username,password);

// now wait for HTTP/1.1 401 Unauthorized and then parse the WWW_Authenticate header
var authenticator= on_www_authenticate(req.header.www_authenticate);
if (authenticator.err) throw err; // or do something similarly drastic

//... now, whenever you make a request, add an Authorization header:
response.setHeader('authorize', authenticator.authorize('GET',url));

## Contributing
In lieu of a formal styleguide, take care to maintain the existing coding style. Add unit tests for any new or changed functionality. Lint and test your code using [Grunt](http://gruntjs.com/).

## Release History
_(Nothing yet)_

## License
Copyright (c) 2013 Randy McLaughlin
Licensed under the MIT license.
