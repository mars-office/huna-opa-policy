package com.huna.authz
import data.com.huna.functions.loggedInUser
import data.com.huna.functions.valid_mtls_certificate

default allow = false

# Is healthcheck URL?
allow {
	regex.match("/api/[\\w-]+/health$", input.url)
}

# Is ota URL?
allow {
	regex.match("/api/ota/[\\w-]+$", input.url)
	valid_mtls_certificate
}

# Is user logged in?
allow {
	not contains(lower(input.url), "/admin/")
	loggedInUser
}

allow {
	contains(lower(input.url), "/admin/")
	loggedInUser
	is_admin
}

user = x {
	x := loggedInUser
}

is_admin {
	loggedInUser.email == data.dataset.adminEmails[_]
}