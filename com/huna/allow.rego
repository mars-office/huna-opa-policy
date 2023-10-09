package com.huna

import data.com.huna.loggedInUser

default allow = false

# Is healthcheck URL?
allow {
	regex.match("/api/[\\w-]+/health$", input.url)
}

# Is user logged in?
allow {
	loggedInUser
}
