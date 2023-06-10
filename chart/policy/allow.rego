package com.huna

default allow = false

# Is healthcheck URL?
allow {
    regex.match("/api/[\\w-]+/health$", input.url)
}

# Is user logged in?
allow {
    input.headers.authorization
    headerParts = split(input.headers.authorization, " ")
    count(headerParts) == 2
    token := headerParts[1]
    validateJwt(token)
}
