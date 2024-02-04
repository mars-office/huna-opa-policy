package com.huna.functions.mtls

decode_and_validate_client_certificate() := decoded {
  input.headers["ssl-client-cert"]
  decodedClientCrt := urlquery.decode(input.headers["ssl-client-cert"])
  mergedCerts := concat("\n", [opa.runtime()["env"]["IOT_CA_CRT"],  decodedClientCrt])
  certs := crypto.x509.parse_certificates(mergedCerts)
  certs[0].Issuer.Organization[0] == "Huna"
  certs[1].Issuer.Organization[0] == "Huna"
  certs[1].Issuer.CommonName = certs[0].Subject.CommonName
  decoded:={"sub": certs[1].Subject.CommonName}
}