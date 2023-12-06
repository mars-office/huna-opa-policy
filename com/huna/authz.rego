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

is_admin = x {
	not loggedInUser
	x:=false
}

is_admin = x {
	loggedInUser
	loggedInUser.email == adminEmails[_]
	x:=true
}