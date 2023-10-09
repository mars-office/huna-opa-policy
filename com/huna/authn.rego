package com.huna

import data.com.huna.env

default insecureTls = false

insecureTls {
	env == "local"
}

# Cache response for 24 hours

idpJwksKeyset(jwksUrl) = http.send({
	"url": jwksUrl,
	"method": "GET",
	"tls_insecure_skip_verify": insecureTls,
	"force_cache": true,
	"raise_error": true,
	"force_cache_duration_seconds": 3600,
}).raw_body

# Cache response for an hour

validateJwt(token) = claims {
	decoded := io.jwt.decode(token)
	headers := decoded[0]
	tempClaims := decoded[1]

	# signature check
	jwks_endpoint := concat("", ["http://huna-dex:5556/keys", "?", urlquery.encode_object({"kid": headers.kid})])
	jwks := idpJwksKeyset(jwks_endpoint)
	io.jwt.verify_rs256(token, jwks)
	claims := tempClaims
}

loggedInUser = user {
	input.headers.authorization
	token := split(input.headers.authorization, " ")[1]
	user := validateJwt(token)
}
