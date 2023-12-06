package com.huna.settings

default env = "local"

env = opa.runtime()["env"]["HUNA_ENVIRONMENT"] {
  opa.runtime()["env"]["HUNA_ENVIRONMENT"]
}