package com.huna.vars

default env = "local"

env = opa.runtime()["env"]["HUNA_ENVIRONMENT"] {
  opa.runtime()["env"]["HUNA_ENVIRONMENT"]
}