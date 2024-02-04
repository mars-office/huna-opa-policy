package com.huna.authz_mtls
import data.com.huna.functions.mtls.decode_and_validate_client_certificate

default allow = false
default user = null
default is_admin = false

allow {
	decode_and_validate_client_certificate
}

user := x {
	x := decode_and_validate_client_certificate
}
