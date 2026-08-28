#!/bin/sh
# Read packaging/targets.tsv -- the single source of truth for what can be
# built and where. Both the local driver and the CI matrix consult this, so the
# target list cannot drift between them.
#
# usage:
#   targets.sh list                    every target id, one per line
#   targets.sh get <id>                "format<TAB>image<TAB>arches"
#   targets.sh supports <id> <arch>    exit 0 supported, 1 not, 2 unknown id
#   targets.sh json [--arches a,b]     CI matrix as {"include":[...]}
set -eu

DIR=$(cd -- "$(dirname -- "$0")" && pwd)
MANIFEST="$DIR/targets.tsv"

[ -f "$MANIFEST" ] || { echo "error: $MANIFEST not found" >&2; exit 2; }

rows() { grep -vE '^[[:space:]]*(#|$)' "$MANIFEST"; }

cmd_list() { rows | awk '{print $1}'; }

cmd_get() {
	[ $# -eq 1 ] || { echo "usage: targets.sh get <id>" >&2; exit 2; }
	_out=$(rows | awk -v id="$1" '$1 == id {printf "%s\t%s\t%s", $2, $3, $4; found=1} END {exit !found}') || {
		echo "error: unknown target '$1' (see $MANIFEST)" >&2
		exit 2
	}
	printf '%s\n' "$_out"
}

cmd_supports() {
	[ $# -eq 2 ] || { echo "usage: targets.sh supports <id> <arch>" >&2; exit 2; }
	_row=$(cmd_get "$1") || exit 2
	_arches=$(printf '%s' "$_row" | cut -f3)
	for _a in $(printf '%s' "$_arches" | tr ',' ' '); do
		[ "$_a" = "$2" ] && return 0
	done
	return 1
}

cmd_json() {
	_want=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--arches) _want="$2"; shift 2 ;;
		*) echo "usage: targets.sh json [--arches a,b]" >&2; exit 2 ;;
		esac
	done

	# One awk pass, not a shell loop: `rows | while ...` runs the loop body in a
	# subshell, so the "have I emitted a row yet" flag would not survive it and
	# the separator logic would silently emit invalid JSON.
	#
	# The runner mapping lives here because it IS the architecture axis: a label
	# that is genuinely that architecture, since nothing emulates.
	rows | awk -v want="$_want" '
	BEGIN { printf "{\"include\":["; first = 1 }
	{
		n = split($4, arches, ",")
		for (i = 1; i <= n; i++) {
			a = arches[i]
			if (want != "") {
				ok = 0
				m = split(want, w, ",")
				for (j = 1; j <= m; j++) if (w[j] == a) ok = 1
				if (!ok) continue
			}
			if (a == "amd64") runner = "ubuntu-latest"
			else if (a == "arm64") runner = "ubuntu-24.04-arm"
			else { print "error: no runner known for arch " a > "/dev/stderr"; exit 2 }
			if (!first) printf ","
			first = 0
			printf "{\"id\":\"%s\",\"format\":\"%s\",\"image\":\"%s\",\"arch\":\"%s\",\"runner\":\"%s\"}", \
				$1, $2, $3, a, runner
		}
	}
	END { printf "]}\n" }'
}

[ $# -ge 1 ] || { echo "usage: targets.sh list|get|supports|json" >&2; exit 2; }
_cmd=$1
shift
case "$_cmd" in
list) cmd_list "$@" ;;
get) cmd_get "$@" ;;
supports) cmd_supports "$@" ;;
json) cmd_json "$@" ;;
*) echo "usage: targets.sh list|get|supports|json" >&2; exit 2 ;;
esac
