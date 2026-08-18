# shellcheck shell=bash
#
# Shared source-staging for the three build scripts. Sourced, not executed.
#
# Builds run from a snapshot rather than the live tree, so a build cannot be
# polluted by local scratch files -- which is not hypothetical here: the Debian
# package used to install ./config.yaml, an untracked gitignored file, and so
# shipped whatever the maintainer happened to have on disk.
#
# Requires: git, tar (rsync only on the non-git fallback path).

stage_source() {
	local dest=$1
	rm -rf "$dest"
	mkdir -p "$dest"

	if git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
		git -C "$PROJECT_ROOT" archive --format=tar HEAD | tar -x -C "$dest"

		# git archive only sees COMMITTED content. Overlay packaging/ and
		# VERSION so an uncommitted packaging change is what actually gets
		# built -- without this, "I fixed the recipe but the build still
		# fails" is a guaranteed half hour.
		#
		# Note "packaging/." and not "packaging": the second form nests the
		# tree as packaging/packaging/ when the destination already exists.
		mkdir -p "$dest/packaging"
		cp -a "$PROJECT_ROOT/packaging/." "$dest/packaging/"
		cp -a "$PROJECT_ROOT/VERSION" "$dest/VERSION"
	else
		# Reached when git refuses the tree, not only when git is absent --
		# running as root over a bind-mounted checkout trips git's
		# safe.directory guard. In a container:
		#   git config --global --add safe.directory '*'
		echo "note: not a usable git tree, falling back to rsync" >&2
		command -v rsync >/dev/null || {
			echo "error: rsync is needed for the non-git path and is not installed" >&2
			return 1
		}
		rsync -a --exclude='.git' --exclude='/rpmbuild' --exclude='/debbuild' \
			--exclude='/archbuild' "$PROJECT_ROOT/" "$dest/"
	fi
}

read_version() {
	# Whitespace stripped so a trailing newline cannot leak into a version string.
	tr -d '[:space:]' < "$PROJECT_ROOT/VERSION"
}
