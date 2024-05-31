package com.huna.functions.oauth

default insecure_tls = false
default env = "local"

env = opa.runtime()["env"]["HUNA_ENVIRONMENT"] {
  opa.runtime()["env"]["HUNA_ENVIRONMENT"]
}

insecure_tls {
	env == "local"
}

get_jwks_keys(jwks_url) = http.send({
	"url": jwks_url,
	"method": "GET",
	"tls_insecure_skip_verify": insecure_tls,
	"force_cache": true,
	"raise_error": true,
	"force_cache_duration_seconds": 3600,
}).raw_body

decode_and_validate_jwt(token) = claims {
	decoded := io.jwt.decode(token)
	headers := decoded[0]
	temp_claims := decoded[1]
	temp_claims.iss == concat("", ["https://idp.", env, ".huna2.com"])
	now_sec := time.now_ns() / 1000000000
	temp_claims.exp > now_sec
	jwks_endpoint := concat("", ["http://huna-idp/keys", "?", urlquery.encode_object({"kid": headers.kid})])
	jwks := get_jwks_keys(jwks_endpoint)
	io.jwt.verify_rs256(token, jwks)
	claims := temp_claims
}

get_logged_in_user() = user {
	input.headers.authorization
	token := split(input.headers.authorization, " ")[1]
	user := decode_and_validate_jwt(token)
}