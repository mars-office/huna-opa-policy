package com.huna.functions.mtls

decode_and_validate_client_certificate() := decoded {
  input.headers["ssl-client-cert"]
  decoded_client_cert := urlquery.decode(input.headers["ssl-client-cert"])
  merged_certs := concat("\n", [opa.runtime()["env"]["ROOT_CA_CRT"], opa.runtime()["env"]["IOT_CA_CRT"],  decoded_client_cert])
  certs := crypto.x509.parse_and_verify_certificates(merged_certs)
  certs[0]
  decoded:={"sub": certs[1][0].Subject.CommonName}
}