# Commonly Used JSON Web Token Utilities JavaScript Library

## Functions

* `decode(encodedJwt)` - Decode the JSON Web Token and return its 3 parts (header, payload, and signature) still in JSON format
* `extractHeader(encodedJwt)` - Decode the JSON Web Token and return just its header as an object
* `extractSignature(encodedJwt)` - Decode the JSON Web Token and return just its signature as an object
* `extractToken(encodedJwt)` - Decode the JSON Web Token and return just its payload as an object
* `verify(encodedJwt)` - Asynchronous function that decodes the JSON Web Token and validate it against Azure AD.  Other validations coming in the future.
