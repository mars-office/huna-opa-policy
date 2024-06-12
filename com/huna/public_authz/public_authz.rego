package com.huna.public_authz
import data.com.huna.authz_oauth

default user = null
default is_admin = false


user := x {
  x:=authz_oauth.user
}

is_admin := x {
  x:=authz_oauth.is_admin
}
