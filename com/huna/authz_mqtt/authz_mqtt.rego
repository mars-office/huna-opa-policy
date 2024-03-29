package com.huna.authz_mqtt

default allow = "deny"

allow := "allow" {
  input.topic == "$SYS/#"
  input.action == "subscribe"
  regex.match("^dashboard?", input.username)
}

allow := "allow" {
  input.topic == "$SYS/#"
  input.peerhost == "127.0.0.1"
}

allow := "allow" {
  input.topic == "#"
  input.peerhost == "127.0.0.1"
}

allow := "allow" {
  input.username == "huna-mqtt-client"
}

allow := "allow" {
  input.action == "publish"
  input.topic == concat("/", ["status", input.username])
}

allow := "allow" {
  input.action == "subscribe"
  input.topic == concat("/", ["commands", input.username])
}