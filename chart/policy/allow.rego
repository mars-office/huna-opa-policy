package com.huna

default allow = false

# Is healthcheck URL?
allow {
    regex.match("/api/[\\w-]+/health$", input.url)
}

# Is user logged in?
allow {
    input.headers.authorization
    token := split(input.headers.authorization, " ")[1]
    validateJwt(token)
}
