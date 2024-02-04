package com.huna.authz
import data.com.huna.authz_mtls
import data.com.huna.authz_mqtt
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


allow := x {
  input.type == "mtls"
  x:=authz_mtls.allow
}

user := x {
  input.type == "mtls"
  x:=authz_mtls.user
}

is_admin := x {
  input.type == "mtls"
  x:=authz_mtls.is_admin
}


allow := x {
  input.type == "mqtt"
  x:=authz_mqtt.allow
}

user := x {
  input.type == "mqtt"
  x:=authz_mqtt.user
}

is_admin := x {
  input.type == "mqtt"
  x:=authz_mqtt.is_admin
}
