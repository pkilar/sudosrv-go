# Building packages for a distribution you are not running

`make rpm`, `make deb` and `make arch` build with the host's own tooling, which
means the host must *be* that distribution and must have its build dependencies
installed. This is the other way: build for any supported distribution in a
clean container, installing nothing on your machine.

## The model

**The container supplies the distribution. The machine supplies the
architecture.**

Nothing in the build mentions an architecture — no `--platform`, no
`--target`, no `GOARCH`, no qemu. A build runs `podman run <image>` and the
resulting package is tagged for whatever the host is, because the builder
genuinely is that. An x86_64 machine produces x86_64 packages for every
distribution; an aarch64 machine produces the aarch64 ones. **Neither can
produce the other's**, and that is deliberate.

Before it builds, the container compares its own `uname -m` against the host's
and refuses if they differ. With binfmt registered, a build could otherwise
silently emulate — producing a correct-looking package very slowly, which is
the failure this design exists to avoid.

## Why not cross-compile or emulate

Cross-compilation is free *today* because both binaries are built
`CGO_ENABLED=0`. It stops being free the moment cgo is required: a cgo binary
links against the build environment's glibc, so building on Fedora and running
on RHEL 9 gives `GLIBC_2.34 not found`. Cross-building it then needs a C
toolchain and a sysroot matched to each *target distribution*, not merely to
the target architecture — Debian has a first-class story for that, RHEL a weak
one, Arch effectively none.

Emulation avoids all of that but costs 5–15× on compilation, and the Arch
recipe runs the race-detector test suite during `check()`.

Native-only is the option that keeps working if this project, or another one
using the same pattern, ever needs cgo.

## Commands

```bash
make targets                  # list the distributions that can be built
make build-package-rhel9      # build one target in a clean container
make lint-package-rhel9       # build it, then lint the result
make lint-packages            # every target this machine's arch supports
```

Or drive it directly:

```bash
./packaging/build-in-container.sh <target-id> [--lint] [--out DIR] [--dry-run]
```

`--dry-run` resolves the target and prints what it would run without starting a
container. Artifacts land in `dist/<target-id>/<arch>/`.

`make lint-packaging-rpm|deb|arch` still work as shorthand for one default
target per format. They are aliases, not the interface — a format can have
several targets now.

## Adding a target

One row in [`packaging/targets.tsv`](../packaging/targets.tsv):

```
# id            format  image                                    arches
rhel9           rpm     registry.access.redhat.com/ubi9/ubi      amd64,arm64
```

The `arches` column is required and load-bearing. The official `archlinux`
image publishes **amd64 only**, so without it CI would schedule an Arch leg
onto an ARM runner and fail for a reason unrelated to the packaging.

Build dependencies are not listed anywhere in the tooling: they are resolved
from the recipe's own declarations (`dnf builddep`, `mk-build-deps`,
`makepkg -s`). That is what lets a new row work without editing the driver.

## Gotchas, each already paid for once

**Builds stage from `git archive HEAD`.** An uncommitted change is not in the
package. Commit first, or you will build your previous revision and wonder why
the fix is missing.

**`GOTOOLCHAIN` is not the same everywhere.** `go.mod` asks for Go 1.27. Red Hat
ships 1.26.7 with `GOTOOLCHAIN=local` patched into `go.env`, so a bare
`go build` fails outright with `go.mod requires go >= 1.27`; Debian leaves it
`auto`. The recipes' explicit `export GOTOOLCHAIN=auto` is what makes RHEL work,
and it needs network access at build time. A sealed builder must vendor a
toolchain instead.

**The distribution's Go must be new enough to bootstrap the one `go.mod` asks
for.** `GOTOOLCHAIN=auto` fetches Go 1.27, but only from a recent enough Go:
1.24 can, 1.22 fails with `toolchain not available`. That is why there is no
`ubuntu-lts` row — Ubuntu 24.04 LTS ships Go 1.22. The recipes' declared floors
(`golang-go (>= 2:1.24~)`, `BuildRequires: golang >= 1.24`) exist so this fails
at dependency resolution, with a name and a version, rather than deep inside
`go clean` where the message says nothing about the cause.

**The protobuf Go code is committed and consumed as-is.** No recipe regenerates
it: `protobuf-compiler` does not exist in any RHEL-family repository, and a
build host's protoc is not the version the committed file was generated with.
CI asserts the committed file is current, where protoc is pinned.

**rpmlint disagrees with itself across versions.** 1.x (RHEL 9) takes `-f` for a
config file and has no unused-filter check; 2.x (Fedora) takes `-r` and reports
unused filters as errors. Both read the `addFilter()` rpmlintrc, so the driver
probes for the flag rather than pinning a version — the point of this tooling is
that each target's own toolchain gets exercised.

**The `archlinux` image sets `NoExtract` for `usr/share/doc/*` and
`usr/share/man/*`.** Docs and man pages are registered by `pacman -Ql` but never
written to disk, so a test asserting a doc file exists fails on a package that
ships it correctly. Assert package ownership, not on-disk presence.
