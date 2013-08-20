var md5= require('./md5');

/*
 * Hide the password. Uses the password to form authorization strings,
 * but provides no interface for exporting it.
 */
function user_credentials(username,password) {
  var basic_string= !password && password !== '' ?
    new Buffer(username, "ascii").toString("base64")
  :
    new Buffer(username+':'+password, "ascii").toString("base64")
  ;
  function basic()
  {
    return basic_string;
  }
  function digest(realm) {
    return !password && password !== '' ?
        md5(username+':'+realm)
        :
        md5(username+':'+realm+':'+password)
  }
  return {
    basic: basic,
    digest: digest,
    username: username
  }
}

module.exports= user_credentials;
