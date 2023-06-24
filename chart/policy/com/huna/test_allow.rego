package com.huna

test_allow_healthcheck {
    data.com.huna.allow with input as {"url": "/api/user-preferences/health"}
}

test_allow_not_logged_in {
    not data.com.huna.allow with input as {"url": "/api/user-preferences/user-preferences"}
}
