target "docker-metadata-action" {}

variable "APP" {
  default = "openldap"
}

variable "VERSION" {
  // renovate: datasource=repology depName=alpine_3_23/openldap
  default = "2.6.10-r0"
}

variable "SOURCE" {
  default = "https://www.openldap.org"
}

group "default" {
  targets = ["image-local"]
}

target "image" {
  inherits = ["docker-metadata-action"]
  args = {
    VERSION = "${VERSION}"
  }
  labels = {
    "org.opencontainers.image.source" = "${SOURCE}"
  }
}

target "image-local" {
  inherits = ["image"]
  output = ["type=docker"]
  tags = ["${APP}:${VERSION}"]
}

target "image-all" {
  inherits = ["image"]
  platforms = [
    "linux/amd64",
    "linux/arm64"
  ]
}
