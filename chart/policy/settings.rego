package com.huna

default env = "local"

env = e {
  opa.runtime()["env"]["HUNA_ENVIRONMENT"]
  e := opa.runtime()["env"]["HUNA_ENVIRONMENT"]
}