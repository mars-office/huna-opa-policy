package com.huna.functions
import data.com.huna.settings.env

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
	tempClaims.iss == concat("", ["https://dex.", env, ".huna2.com"])
	nowSec := ((time.now_ns() / 1000) / 1000) / 1000
	tempClaims.exp > nowSec

	# signature check
	jwks_endpoint := concat("", ["http://huna-dex:5556/keys", "?", urlquery.encode_object({"kid": headers.kid})])
	jwks := idpJwksKeyset(jwks_endpoint)
	io.jwt.verify_rs256(token, jwks)

	claims := tempClaims
}

loggedInUser := user {
	input.headers.authorization
	token := split(input.headers.authorization, " ")[1]
	user := validateJwt(token)
}

valid_mtls_certificate {
	input.headers["ssl-client-cert"]
	decodedClientCrt := urlquery.decode(input.headers["ssl-client-cert"])
  mergedCerts := concat("\n", [data.interimcacrt, data.cacrt,  decodedClientCrt])
  certs := crypto.x509.parse_certificates(mergedCerts)
  certs[0].Issuer.Organization[0] == "Huna"
  certs[1].Issuer.Organization[0] == "Huna"
  certs[2].Issuer.Organization[0] == "Huna"
  certs[2].Issuer.CommonName = certs[1].Subject.CommonName
}