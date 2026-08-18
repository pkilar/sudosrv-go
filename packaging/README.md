# Packaging

Everything this project ships as a native package lives here, so "what does
sudosrv install?" has one answer rather than three.

```
VERSION                          one line, no leading "v" -- the only place the version is written
packaging/
├── config/sudosrv.yaml          ┐
├── logrotate/sudosrv.logrotate  │
├── systemd/sudosrv.service      │ SHARED: one copy, installed by every format
├── sysusers/sudosrv.conf        │ that needs it
├── tmpfiles/sudosrv.conf        │
├── man/{sudosrv,logsh}.8        │
├── logsh/logsh-install.sh       ┘
├── stage-source.sh              shared source-snapshot staging
├── rpm/    sudosrv.spec       + build-rpm.sh
├── debian/ control rules ...  + build-deb.sh
└── arch/   PKGBUILD          + build-arch.sh
```

## Building

```sh
make rpm     # or ./packaging/rpm/build-rpm.sh
make deb     # or ./packaging/debian/build-deb.sh
make arch    # or ./packaging/arch/build-arch.sh   (not as root; makepkg refuses)
```

Each script resolves the project root independently of your working directory,
reads `VERSION`, stages a snapshot into a gitignored build tree
(`rpmbuild/`, `debbuild/`, `archbuild/`), injects the version into that format's
field **in the staged copy**, and runs the native builder. The committed
`pkgver` and `Version:` are deliberately implausible placeholders so a package
built by calling the native tool directly cannot be mistaken for a release.

Building needs network access: the module requires Go 1.26.3, which neither
Debian trixie nor Fedora 43 ships, so each recipe sets `GOTOOLCHAIN=auto` and
lets the distribution toolchain fetch the one it needs. A sealed builder
(`mock` without `--enable-network`, koji) must vendor a toolchain instead.

The RPM script builds for the host architecture only. It used to loop over
x86_64 and aarch64 passing `--target`, but `%build` runs `make build` with no
`GOARCH`, so the "aarch64" package contained an x86_64 binary under an aarch64
tag. Build on the target architecture.

## The shared tier

Anything used by more than one format has exactly one copy, and each recipe
installs *that* path. This is not tidiness: the per-format copies it replaces
had already drifted. The Arch and RPM default configs differed, the Arch unit
had lost its trailing newline, Debian shipped no logrotate config at all, and
Debian installed an untracked `config.yaml` from the repo root — so the package
failed to build from a clean checkout and, on a maintainer's machine, shipped
that machine's local settings to every user.

`TestEveryFormatInstallsTheSharedAssets` and `TestNoSharedAssetIsOrphaned` in
`internal/logshell/packaging_test.go` enforce it: adding a file here without
recording which formats install it fails the suite.

## What legitimately differs

| Concern | RPM | Debian | Arch |
|---|---|---|---|
| logsh binary | `/usr/sbin` | `/usr/sbin` | **`/usr/bin`** — usr-merged, `/usr/sbin` is owned by `filesystem` |
| logsh helper dir | `/usr/libexec/logsh` | `/usr/libexec/logsh` | `/usr/lib/logsh` |
| Service account | `%pre` + `useradd` | `sysusers.d` | `sysusers.d` |
| State directories | `%attr` in `%files` | `tmpfiles.d` | `tmpfiles.d` |
| `/bin/kill` for `ExecReload` | `util-linux` | `procps` | `procps-ng` |

The RPM creates its account with `useradd` rather than `sysusers.d` because the
sysusers macro is not available on every RPM distribution this targets. Both
produce the same account, and the `-` shell field in the shared sysusers file
lets systemd substitute each distribution's own nologin path.

## Verification

Recipes that parse prove nothing. The standard is that a package manager has
installed the built package, and then upgraded it, in a clean container — see
the verification section of `docs/logsh-deployment.md`.
