variable "BUILD_CONFIGURATION" {
  default = "dev"
  type = string
  description = "Build configuration of the application (dev|release)"
  validation {
    condition = equal(regex("^dev$|^release$", BUILD_CONFIGURATION), BUILD_CONFIGURATION)
    error_message = "BUILD_CONFIGURATION must be 'dev' or 'release'"
  }
}

variable "VERSION" {
  default = "dev"
  type = string
  description = "Version of the application"
  validation {
    condition = equal(regex("^$|^dev$|^[0-9]+.[0-9]+.[0-9]+$", VERSION), VERSION)
  }
}

// Base target for shared configuration
target "docker-metadata-action" {
  tags = ["msgtausch:${VERSION}"]
}

// Build target for creating builder base
target "builder-base" {
  target = "builder"
  dockerfile = "Dockerfile"
}

// Target for generating templ files
target "templ" {
  target = "templ-generate"
  dockerfile = "Dockerfile"
  output = ["type=cacheonly"]
}

// Target for verifying code formatting with gofmt
target "format" {
  target = "format-check"
  dockerfile = "Dockerfile"
  output = ["type=cacheonly"]
}

// Target for running tests
target "test" {
  target = "unit-test"
  dockerfile = "Dockerfile"
  output = ["type=cacheonly"]
}

// Target for development build
target "build" {
  target = "runtime-${BUILD_CONFIGURATION}"
  platforms = [
    "linux/amd64",
    "linux/arm64",
    "linux/riscv64",
    "darwin/amd64",
    "darwin/arm64",
    "windows/amd64"
  ]
  output = ["./bin"]
}

target "simulation" {
  target = "simulation"
  dockerfile = "Dockerfile"
  output = ["type=cacheonly"]
}

// Target for running compose-intercept integration tests
target "compose-intercept-test" {
  context = "./tests/compose-intercept"
  dockerfile-inline = <<EOF
FROM docker/compose:2.23.3
RUN apk add --no-cache bash curl
WORKDIR /test
COPY . .
CMD ["docker-compose", "up", "--build", "--abort-on-container-exit", "--exit-code-from", "client"]
EOF
  output = ["type=cacheonly"]
}

target "nix" {
  target = "nix-build"
  dockerfile = "Dockerfile"
  output = ["type=cacheonly"]
}

// Target for creating release artifacts
target "release" {
  inherits = ["build"]
  tags = ["msgtausch:${VERSION}"]
  output = ["./release"]
}

// Default group including tests and build
group "default" {
  targets = ["templ", "format", "test", "build"]
}

// CI group for continuous integration
group "ci" {
  targets = ["templ", "format", "test", "compose-intercept-test", "release"]
}
