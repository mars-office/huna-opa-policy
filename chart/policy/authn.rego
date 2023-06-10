package com.huna

default insecureTls = false

insecureTls = true {
  env == "local"
}

idpMetadata(issuerUrl) := http.send({
    "url": concat("", [issuerUrl, "/.well-known/openid-configuration"]),
    "method": "GET",
    "force_cache": true,
    "raise_error": true,
    "tls_insecure_skip_verify": insecureTls,
    "force_cache_duration_seconds": 86400 # Cache response for 24 hours
}).body

idpJwksKeyset(jwksUrl) := http.send({
    "url": jwksUrl,
    "method": "GET",
    "tls_insecure_skip_verify": insecureTls,
    "force_cache": true,
    "raise_error": true,
    "force_cache_duration_seconds": 3600 # Cache response for an hour
}).raw_body

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