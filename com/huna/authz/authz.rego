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

# Is detection URL?
allow {
	regex.match("/api/detection/[\\w-]+$", input.url)
	valid_mtls_certificate
}

# Is user logged in?
allow {
    not regex.match("/api/ota/[\\w-]+$", input.url)
	not regex.match("/api/detection/[\\w-]+$", input.url)
	not contains(lower(input.url), "/admin/")
	loggedInUser
}

allow {
    not regex.match("/api/ota/[\\w-]+$", input.url)
	not regex.match("/api/detection/[\\w-]+$", input.url)
	contains(lower(input.url), "/admin/")
	loggedInUser
	is_admin
}

user := x {
    not regex.match("/api/ota/[\\w-]+$", input.url)
	not regex.match("/api/detection/[\\w-]+$", input.url)
	x := loggedInUser
}

user := x {
    regex.match("/api/ota/[\\w-]+$", input.url)
	x := valid_mtls_certificate
}

user := x {
    regex.match("/api/detection/[\\w-]+$", input.url)
	x := valid_mtls_certificate
}

is_admin {
    not regex.match("/api/detection/[\\w-]+$", input.url)
	not regex.match("/api/ota/[\\w-]+$", input.url)
	loggedInUser.email == data.dataset.adminEmails[_]
}