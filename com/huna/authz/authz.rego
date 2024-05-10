package com.huna.authz
import data.com.huna.authz_oauth


default allow = false
default user = null
default is_admin = false

allow := x {
  input.type == "oauth"
  x:=authz_oauth.allow
}

user := x {
  input.type == "oauth"
  x:=authz_oauth.user
}

is_admin := x {
  input.type == "oauth"
  x:=authz_oauth.is_admin
}
