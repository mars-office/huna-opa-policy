package com.huna

default allow = false

# Is healthcheck URL?
allow {
    regex.match("/api/[\\w-]+/health", input.url)
}

