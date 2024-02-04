package com.huna.authz_oauth
import data.com.huna.functions.oauth.get_logged_in_user

default allow = false
default user = null
default is_admin = false

allow {
	not contains(lower(input.url), "/admin/")
	get_logged_in_user
}

allow {
	contains(lower(input.url), "/admin/")
	get_logged_in_user
	is_admin
}

user := x {
	x := get_logged_in_user
}

is_admin {
	get_logged_in_user.email == data.dataset.adminEmails[_]
}