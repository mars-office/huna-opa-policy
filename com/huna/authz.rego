package com.huna.authz
import data.com.huna.functions.loggedInUser

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