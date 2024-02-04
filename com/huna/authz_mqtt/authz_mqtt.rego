package com.huna.authz_mqtt
import future.keywords.in

default allow = "deny"

allow := "allow" {
  input.username == "huna-mqtt-client"
}

allow := "allow" {
  input.topic == concat("/", ["status", input.username])
}

allow := "allow" {
  input.topic == "$SYS/#"
  input.action == "subscribe"
  regex.match("^dashboard?", input.username)
}