package com.huna.authz
import data.com.huna.functions.loggedInUser
import data.com.huna.constants.adminEmails

default allow = false

# Is healthcheck URL?
allow {
	regex.match("/api/[\\w-]+/health$", input.url)
}

# Is user logged in?
allow {
	loggedInUser
}

user = x {
	x := loggedInUser
}

is_admin = {
	loggedInUser
	loggedInUser["email"]
	loggedInUser["email"] = adminEmails[_]
}