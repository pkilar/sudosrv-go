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

Building needs network access: the module requires Go 1.27, which neither
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
| Service account | `sysusers.d` via `%sysusers_create_compat` | `sysusers.d` via `dh_installsysusers` | `sysusers.d` via a pacman hook |
| State directories | `%attr` in `%files`, plus `tmpfiles.d` | `tmpfiles.d` | `tmpfiles.d` |
| `/bin/kill` for `ExecReload` | `util-linux` | `procps` | `procps-ng` |

All three create the account from the same `sysusers.d` file; the `-` shell
field lets systemd substitute each distribution's own nologin path, which is at
`/usr/sbin/nologin` on Debian and `/usr/bin/nologin` on Arch. The RPM must ship
that file for a second reason: rpm generates `Requires: user(sudosrv)` from the
`%attr` entries in `%files`, and without a `sysusers.d` file nothing provides
it, so dnf refuses the transaction outright. The hand-written `groupadd`/
`useradd` this replaces created the same account but generated no such Provides.

Each format needs its own opt-in to get there, and none of them is the default:
the RPM needs `%{?sysusers_requires_compat}` and `%sysusers_create_compat`
(`%tmpfiles_create_compat` does not exist -- `%tmpfiles_create` is the macro),
Debian needs `dh $@ --with installsysusers` because `dh_installsysusers` only
joins the default sequence at compat 14, and its input file must exist before
`dpkg-buildpackage` starts, since `dh` decides which commands to skip before
`debian/rules` ever runs.

## Verification

Recipes that parse prove nothing. The standard is that a package manager has
installed the built package, and then upgraded it, in a clean container — see
the verification section of `docs/logsh-deployment.md`.
