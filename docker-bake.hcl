variable "BUILD_CONFIGURATION" {
  default = "dev"
  type    = string
  validation {
    condition     = contains(["dev", "release"], BUILD_CONFIGURATION)
    error_message = "BUILD_CONFIGURATION must be dev or release"
  }
}

variable "VERSION" {
  default = "dev"
  type    = string
}

variable "IMAGE" {
  default = "codefionn/msgtausch"
  type    = string
}

# docker/metadata-action writes an override for this target in release CI. The
# default keeps `docker buildx bake release` useful outside CI as well.
target "docker-metadata-action" {
  tags = ["${IMAGE}:${VERSION}"]
}

target "checks" {
  context    = "."
  dockerfile = "Dockerfile"
}

target "format" {
  inherits = ["checks"]
  target   = "format-check"
  output   = ["type=cacheonly"]
}

target "test" {
  inherits = ["checks"]
  target   = "test"
  output   = ["type=cacheonly"]
}

target "clippy" {
  inherits = ["checks"]
  target   = "clippy"
  output   = ["type=cacheonly"]
}

target "simulation" {
  inherits = ["checks"]
  target   = "simulation"
  output   = ["type=cacheonly"]
}

# Keep loopback performance checks native. `checks` has no platforms setting,
# so this stage runs on BUILDPLATFORM even when image targets build arm64 too.
target "throughput" {
  inherits = ["checks"]
  target   = "throughput"
  output   = ["type=cacheonly"]
}

target "nix" {
  inherits = ["checks"]
  target   = "nix-build"
  output   = ["type=cacheonly"]
}

target "runtime" {
  inherits = ["checks"]
  target   = "runtime-${BUILD_CONFIGURATION}"
  args = {
    VERSION = VERSION
  }
}

target "artifact" {
  inherits = ["checks"]
  target   = "binary"
  args = {
    VERSION = VERSION
  }
}

# A local exporter cannot put both platform binaries at the same path. Keep the
# directories explicit so a developer can inspect or attach both artifacts.
target "binary-amd64" {
  inherits  = ["artifact"]
  platforms = ["linux/amd64"]
  output    = ["type=local,dest=./bin/linux-amd64"]
}

target "binary-arm64" {
  inherits  = ["artifact"]
  platforms = ["linux/arm64"]
  output    = ["type=local,dest=./bin/linux-arm64"]
}

# A single OCI archive carries both manifests and is the right local artifact
# for containerd, oras, or another OCI-aware tool.
target "image" {
  inherits  = ["runtime", "docker-metadata-action"]
  platforms = ["linux/amd64", "linux/arm64"]
  output    = ["type=oci,dest=./dist/msgtausch-${VERSION}.oci"]
}

# Registry export creates and pushes one manifest list with both architectures.
target "release" {
  inherits  = ["runtime", "docker-metadata-action"]
  platforms = ["linux/amd64", "linux/arm64"]
  output    = ["type=registry"]
}

group "build" {
  targets = ["binary-amd64", "binary-arm64"]
}

group "default" {
  targets = ["format", "test", "clippy", "simulation", "throughput", "binary-amd64", "binary-arm64"]
}

group "ci" {
  targets = ["format", "test", "clippy", "simulation", "throughput", "nix", "image"]
}
