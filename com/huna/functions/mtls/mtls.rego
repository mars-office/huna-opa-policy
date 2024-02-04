package com.huna.functions.mtls

decode_and_validate_client_certificate() := decoded {
  input.headers["ssl-client-cert"]
  decoded_client_cert := urlquery.decode(input.headers["ssl-client-cert"])
  merged_certs := concat("\n", [opa.runtime()["env"]["IOT_CA_CRT"],  decoded_client_cert])
  certs := crypto.x509.parse_certificates(merged_certs)
  certs[0].Issuer.Organization[0] == "Huna"
  certs[1].Issuer.Organization[0] == "Huna"
  certs[1].Issuer.CommonName = certs[0].Subject.CommonName
  decoded:={"sub": certs[1].Subject.CommonName}
}