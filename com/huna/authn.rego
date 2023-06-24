package com.huna

default insecureTls = false

insecureTls {
	env == "local"
}

idpMetadata(issuerUrl) := http.send({
	"url": concat("", [issuerUrl, "/.well-known/openid-configuration"]),
	"method": "GET",
	"force_cache": true,
	"raise_error": true,
	"tls_insecure_skip_verify": insecureTls,
	"force_cache_duration_seconds": 86400,
}).body

# Cache response for 24 hours

idpJwksKeyset(jwksUrl) := http.send({
	"url": jwksUrl,
	"method": "GET",
	"tls_insecure_skip_verify": insecureTls,
	"force_cache": true,
	"raise_error": true,
	"force_cache_duration_seconds": 3600,
}).raw_body

# Cache response for an hour

validateJwt(token) := claims {
	decoded := io.jwt.decode(token)
	headers := decoded[0]
	tempClaims := decoded[1]

	# signature check
	metadata := idpMetadata(tempClaims.iss)
	jwks_endpoint := concat("", [metadata.jwks_uri, "?", urlquery.encode_object({"kid": headers.kid})])
	jwks := idpJwksKeyset(jwks_endpoint)
	io.jwt.verify_rs256(token, jwks)
	claims := tempClaims
}

getLoggedInUser := user {
	input.headers.authorization
	token := split(input.headers.authorization, " ")[1]
	user := validateJwt(token)
}
