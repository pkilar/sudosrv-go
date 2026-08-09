#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Filename: packaging/logsh/logsh-install.sh
#
# Install, enable, disable and remove logsh, the recording login shell.
#
# This script exists because the ORDER of these steps decides whether a mistake
# costs an audit gap or costs every administrator their login. Distribution
# packaging (deb postinst, rpm %post, Arch .install) calls it rather than
# reimplementing the sequence three times and getting it subtly different.
#
# The rule it enforces:
#
#   install  -> binary, symlinks, /etc/shells, config. Changes NO passwd entry.
#   verify   -> logsh -validate and -selftest. Must pass before enable.
#   enable   -> point an account's shell at a logsh symlink. One account.
#   disable  -> point it back. Always available, never needs the binary to work.
#   uninstall-> shells restored FIRST, then files removed.
#
# Nothing here switches an account to logsh automatically. A package that did
# that would turn `apt upgrade` into a fleet-wide lockout the first time a
# config was wrong.
#
# All paths honour $ROOT so the whole thing can be exercised against a scratch
# directory; the test suite does exactly that.

set -eu

ROOT="${ROOT:-}"
SBINDIR="${SBINDIR:-/usr/sbin}"
CONFDIR="${CONFDIR:-/etc/logsh}"
SHELLS_FILE="${SHELLS_FILE:-/etc/shells}"
PASSWD_FILE="${PASSWD_FILE:-/etc/passwd}"

BINARY="$SBINDIR/logsh"
CONFIG="$CONFDIR/logsh.yaml"

# The names installed as symlinks. Keep in step with the shells map in the
# shipped config: a symlink with no mapping is refused at login, and a mapping
# with no symlink is simply unreachable.
SYMLINKS="lsh lbash lzsh ldash"

r() { printf '%s%s' "$ROOT" "$1"; }

die() { printf 'logsh-install: %s\n' "$*" >&2; exit 1; }
note() { printf 'logsh-install: %s\n' "$*"; }

usage() {
	cat >&2 <<'USAGE'
usage: logsh-install.sh <command> [args]

  install                 install binary, symlinks, /etc/shells entries, config
  verify                  run logsh -validate and -selftest
  enable <user> <name>    set <user>'s shell to the <name> symlink (e.g. lbash)
  disable <user> <shell>  set <user>'s shell back to <shell> (e.g. /bin/bash)
  uninstall               restore shells, then remove symlinks and /etc/shells entries

Environment: ROOT, SBINDIR, CONFDIR, SHELLS_FILE, PASSWD_FILE
USAGE
	exit 2
}

# add_shell registers one path in /etc/shells.
#
# chsh and several daemons refuse an account whose shell is not listed, so an
# unregistered symlink is an account that cannot be switched to it. Idempotent:
# packaging runs this on every upgrade.
add_shell() {
	_path="$1"
	_file="$(r "$SHELLS_FILE")"
	[ -f "$_file" ] || : > "$_file"
	if ! grep -qxF "$_path" "$_file"; then
		printf '%s\n' "$_path" >> "$_file"
		note "registered $_path in $SHELLS_FILE"
	fi
}

# remove_shell deregisters one path.
remove_shell() {
	_path="$1"
	_file="$(r "$SHELLS_FILE")"
	[ -f "$_file" ] || return 0
	_tmp="$_file.logsh.$$"
	grep -vxF "$_path" "$_file" > "$_tmp" || true
	cat "$_tmp" > "$_file"
	rm -f "$_tmp"
}

# users_with_shell lists accounts whose login shell is exactly $1.
users_with_shell() {
	_shell="$1"
	_file="$(r "$PASSWD_FILE")"
	[ -f "$_file" ] || return 0
	awk -F: -v s="$_shell" '$7 == s { print $1 }' "$_file"
}

# set_shell rewrites one account's shell field in place.
#
# It edits $PASSWD_FILE directly rather than calling chsh(1) so that it works
# against a scratch root under test, and so that it cannot fail because the
# target shell is momentarily absent from /etc/shells.
set_shell() {
	_user="$1"; _shell="$2"
	_file="$(r "$PASSWD_FILE")"
	[ -f "$_file" ] || die "$PASSWD_FILE not found"
	grep -q "^$_user:" "$_file" || die "no such account: $_user"

	_tmp="$_file.logsh.$$"
	awk -F: -v OFS=: -v u="$_user" -v s="$_shell" \
		'$1 == u { $7 = s } { print }' "$_file" > "$_tmp"
	# Preserve the original inode and mode: replacing /etc/passwd wholesale with
	# a fresh file is how its permissions get quietly widened.
	cat "$_tmp" > "$_file"
	rm -f "$_tmp"
	note "$_user -> $_shell"
}

cmd_install() {
	[ -x "$(r "$BINARY")" ] || die "$BINARY is missing or not executable; install it first"

	for name in $SYMLINKS; do
		ln -sf logsh "$(r "$SBINDIR/$name")"
		add_shell "$SBINDIR/$name"
	done

	mkdir -p "$(r "$CONFDIR")"
	chmod 0755 "$(r "$CONFDIR")"
	if [ ! -f "$(r "$CONFIG")" ]; then
		note "no $CONFIG present; install one before enabling any account"
	fi
	note "installed. NO account has been switched; run 'verify' then 'enable'."
}

cmd_verify() {
	_bin="$(r "$BINARY")"
	[ -x "$_bin" ] || die "$BINARY is missing or not executable"
	[ -f "$(r "$CONFIG")" ] || die "$CONFIG is missing; logsh would refuse every session"

	"$_bin" -validate -config "$(r "$CONFIG")" || die "configuration did not validate"
	"$_bin" -selftest -config "$(r "$CONFIG")" || die "selftest failed"
	note "verify passed"
}

cmd_enable() {
	[ $# -eq 2 ] || usage
	_user="$1"; _name="$2"
	_target="$SBINDIR/$_name"

	# Refuse to switch an account to a shell that cannot work. This is the last
	# point at which a mistake is free.
	[ -L "$(r "$_target")" ] || die "$_target is not installed"
	cmd_verify
	grep -qxF "$_target" "$(r "$SHELLS_FILE")" || die "$_target is not in $SHELLS_FILE"

	set_shell "$_user" "$_target"
	note "REMINDER: keep an open root session until you have confirmed a new login works."
}

cmd_disable() {
	[ $# -eq 2 ] || usage
	set_shell "$1" "$2"
}

# cmd_uninstall restores every account BEFORE removing anything.
#
# The other order is a fleet-wide lockout: delete the symlinks first and every
# account still pointing at one has a login shell that does not exist. Package
# removal must never be able to do that, which is why this runs from prerm and
# not postrm.
cmd_uninstall() {
	_fallback="${FALLBACK_SHELL:-/bin/sh}"

	for name in $SYMLINKS; do
		_target="$SBINDIR/$name"
		for u in $(users_with_shell "$_target"); do
			note "restoring $u from $_target to $_fallback"
			set_shell "$u" "$_fallback"
		done
	done

	for name in $SYMLINKS; do
		remove_shell "$SBINDIR/$name"
		rm -f "$(r "$SBINDIR/$name")"
	done
	note "uninstalled; $CONFIG and any spooled journals were left in place"
}

[ $# -ge 1 ] || usage
command="$1"; shift
case "$command" in
	install)   cmd_install "$@" ;;
	verify)    cmd_verify "$@" ;;
	enable)    cmd_enable "$@" ;;
	disable)   cmd_disable "$@" ;;
	uninstall) cmd_uninstall "$@" ;;
	*)         usage ;;
esac
