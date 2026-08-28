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
# The multi-call names this build installs.
SYMLINKS="lsh lbash lzsh"

# Names this build NO LONGER installs, but that an account on a host installed
# by an earlier version may still be using. `install` never created these, so
# nothing here brings them back -- but uninstall must still restore accounts
# from them and clean them out of /etc/shells. Dropping a name from SYMLINKS
# without listing it here leaves such an account pointing at a symlink to a
# binary that removal just deleted, which is a login nobody can use and the
# exact failure the ordering in cmd_uninstall exists to prevent.
LEGACY_SYMLINKS="ldash"

# The forced-command entry point. Installed as a symlink like the shell names
# above, but deliberately NOT registered in /etc/shells: it is not a shell, and
# listing it there would let an account be chsh'd to it.
ENTRY_SYMLINKS="logsh-entry"

# Where the search for a live ForceCommand reference starts. The full set of
# files is RESOLVED from these, not assumed -- see entry_in_sshd_config.
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_CONFIG_DIR="${SSHD_CONFIG_DIR:-/etc/ssh/sshd_config.d}"
# sshd_config(5): "Files without absolute paths are assumed to be in /etc/ssh."
SSHD_INCLUDE_BASE="${SSHD_INCLUDE_BASE:-/etc/ssh}"
# OpenSSH refuses to nest Include beyond this depth. Matching it means a config
# that includes itself terminates here too instead of recursing forever.
SSHD_INCLUDE_MAX_DEPTH=16

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
                          (--force, or LOGSH_FORCE_UNINSTALL=1, overrides the
                          sshd reference check)
  check-sshd              exit non-zero if sshd still references logsh-entry;
                          changes nothing (used by the pacman removal hook)

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

	for name in $ENTRY_SYMLINKS; do
		ln -sf logsh "$(r "$SBINDIR/$name")"
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

# entry_in_sshd_config prints every sshd config line naming the entry symlink.
#
# Removing the package deletes /usr/sbin/logsh-entry. On a host whose sshd_config
# says `ForceCommand /usr/sbin/logsh-entry`, that is root's SSH access to the
# host, gone -- and unlike the passwd-shell case, no account is switched, so the
# existing restore-before-remove ordering does not cover it.
sshd_include_targets() {
	_file="$1"
	_depth="$2"

	# Every guard is an explicit `if` rather than `[ ... ] && return`: this
	# script runs under `set -e`, and a trailing && list that evaluates false
	# becomes the function's exit status and aborts the caller.
	if [ "$_depth" -ge "$SSHD_INCLUDE_MAX_DEPTH" ]; then
		return 0
	fi
	if [ ! -f "$_file" ]; then
		return 0
	fi
	if [ ! -r "$_file" ]; then
		# Unreadable, so its Include directives cannot be enumerated. The
		# caller greps this path too and reports it as a hit, so the
		# uninstall refuses rather than proceeding on a partial picture.
		return 0
	fi

	# One Include may name several paths, each of which may be a glob.
	sed -n 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]][[:space:]]*//p' "$_file" |
		while IFS= read -r _spec; do
			for _pat in $_spec; do
				case "$_pat" in
				/*) _abs="$_pat" ;;
				*) _abs="$SSHD_INCLUDE_BASE/$_pat" ;;
				esac
				# Unquoted so the shell expands the glob, and prefixed so a
				# scratch root under $ROOT is searched rather than the real
				# system config. A pattern that matches nothing survives
				# literally and is dropped by the existence check.
				_glob="$(r "$_abs")"
				for _hit in $_glob; do
					if [ -e "$_hit" ]; then
						printf '%s\n' "$_hit"
						sshd_include_targets "$_hit" "$((_depth + 1))"
					fi
				done
			done
		done
	return 0
}

entry_in_sshd_config() {
	# The set of files sshd reads is not a fixed list. sshd_config pulls in
	# more with Include, whose targets may be globs and may live anywhere on
	# the filesystem -- and on most distributions the drop-in directory is
	# reached that way rather than by convention. Searching only the two
	# conventional paths would miss a ForceCommand in an included file and let
	# uninstall delete the binary sshd still names, which is precisely the
	# lockout this guard exists to prevent. So the list is resolved by
	# following Include from the top-level config, keeping the drop-in
	# directory as a seed for configs that do not include it themselves.
	#
	# This over-refuses by design: it greps text rather than evaluating sshd's
	# effective configuration, so a commented-out or Match-scoped directive
	# trips it too. `sshd -T -C user=root,host=...,addr=...` is the
	# authoritative view of what sshd would actually apply; --force is the
	# override once an operator has checked.
	_top="$(r "$SSHD_CONFIG")"
	_paths="$(
		printf '%s\n%s\n' "$_top" "$(r "$SSHD_CONFIG_DIR")"
		sshd_include_targets "$_top" 0
	)"

	# sort -u so a file reached both as a seed and via Include is reported once.
	for _p in $(printf '%s\n' "$_paths" | sort -u); do
		if [ ! -e "$_p" ]; then
			continue
		fi

		# grep's exit status carries three cases and they must not be
		# conflated: 0 is a match, 1 is a clean no-match, anything above 1 is
		# an error -- most plausibly a config this process cannot read.
		# Discarding stderr and forcing success would make that third case
		# look identical to the second, so an unreadable sshd_config would
		# read as "no reference" and uninstall would proceed to delete the
		# symlink that config still names. That is fail-OPEN on a guard whose
		# whole purpose is preventing a lockout, so an unreadable path is
		# reported as a hit instead: refuse, and let --force be the deliberate
		# override.
		#
		# The assignment sits in an `if` condition deliberately: under `set -e`
		# a bare assignment from a failing command substitution would abort the
		# whole uninstall the moment grep reported no-match. A condition is
		# exempt from that.
		if _out="$(grep -rn "logsh-entry" "$_p" 2>&1)"; then
			printf '%s\n' "$_out"
		elif [ $? -ne 1 ]; then
			printf '%s: cannot be read, so it cannot be cleared of references (%s)\n' \
				"$_p" "$_out"
		fi
	done
	return 0
}

# report_sshd_refusal prints why a removal is being refused. Shared so the
# uninstall path and the pre-transaction check cannot drift apart in wording.
report_sshd_refusal() {
	printf 'logsh-install: refusing to uninstall: sshd still references logsh-entry\n' >&2
	printf '%s\n' "$1" >&2
	# Both overrides are named because the caller decides which is reachable:
	# --force works for a direct invocation and from prerm/%preun, but pacman
	# offers no way to pass a flag through to a hook, so on Arch the environment
	# variable is the only one an operator can actually use.
	printf 'logsh-install: remove the reference and reload sshd first, or override with\n' >&2
	printf '  --force                       (direct invocation)\n' >&2
	printf '  LOGSH_FORCE_UNINSTALL=1       (e.g. sudo -E LOGSH_FORCE_UNINSTALL=1 pacman -R logsh)\n' >&2
}

# cmd_check_sshd reports whether sshd still references the entry symlink and
# exits non-zero if it does. It changes nothing.
#
# This exists because pacman does not honour a failing pre_remove. dpkg aborts
# on a failing prerm and rpm aborts on a failing %preun, so on those two the
# refusal inside cmd_uninstall is the whole guard. pacman prints the error,
# removes the package anyway, and still exits 0 -- which leaves every switched
# account pointing at a symlink that no longer exists. The only pacman
# mechanism that can abort a transaction is a PreTransaction hook with
# AbortOnFail, and such a hook must not restore accounts, because the
# transaction it is vetting may still be cancelled. Hence a check that is pure.
#
# LOGSH_FORCE_UNINSTALL is the override for that path, since pacman offers no
# way to pass --force through to a hook. It matters because the guard treats an
# unreadable config as a reference: without an escape hatch, a host whose
# sshd_config cannot be read would refuse removal forever.
cmd_check_sshd() {
	if [ "${LOGSH_FORCE_UNINSTALL:-}" = 1 ]; then
		return 0
	fi
	_hits="$(entry_in_sshd_config)"
	if [ -n "$_hits" ]; then
		report_sshd_refusal "$_hits"
		exit 1
	fi
}

# cmd_uninstall restores every account BEFORE removing anything.
#
# The other order is a fleet-wide lockout: delete the symlinks first and every
# account still pointing at one has a login shell that does not exist. Package
# removal must never be able to do that, which is why this runs from prerm and
# not postrm.
cmd_uninstall() {
	# LOGSH_FORCE_UNINSTALL is honoured here as well as in check-sshd, because
	# the hook and this function are two halves of one removal. If an operator
	# forced past the pre-transaction hook and this still refused, pacman would
	# ignore the refusal and remove the package anyway -- with no account
	# restored, which is the very lockout the guard exists to prevent. Forcing
	# the removal has to force the restore with it.
	#
	# Separate `if`s rather than a `&&` list: under `set -e` a trailing && list
	# that evaluates false becomes the function's exit status and aborts the
	# caller.
	_force=0
	if [ "${1:-}" = "--force" ]; then
		_force=1
	fi
	if [ "${LOGSH_FORCE_UNINSTALL:-}" = 1 ]; then
		_force=1
	fi

	_hits="$(entry_in_sshd_config)"
	if [ -n "$_hits" ] && [ "$_force" -eq 0 ]; then
		report_sshd_refusal "$_hits"
		exit 1
	fi

	_fallback="${FALLBACK_SHELL:-/bin/sh}"

	for name in $SYMLINKS $LEGACY_SYMLINKS; do
		_target="$SBINDIR/$name"
		for u in $(users_with_shell "$_target"); do
			note "restoring $u from $_target to $_fallback"
			set_shell "$u" "$_fallback"
		done
	done

	for name in $SYMLINKS $LEGACY_SYMLINKS; do
		remove_shell "$SBINDIR/$name"
		rm -f "$(r "$SBINDIR/$name")"
	done
	for name in $ENTRY_SYMLINKS; do
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
	check-sshd) cmd_check_sshd "$@" ;;
	*)         usage ;;
esac
