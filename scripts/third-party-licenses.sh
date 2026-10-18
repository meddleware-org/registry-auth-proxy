#!/bin/sh
# Writes the licence texts of everything redistributed in the registry-auth-proxy image besides the service
# itself: the Go standard library compiled into the binary (BSD-3-Clause), the Mozilla CA certificate bundle
# copied into the image (MPL-2.0, through the Debian ca-certificates copyright file), and any third-party Go
# module the build graph of ./cmd/server pulls in (none today; the module is standard-library only). The
# Dockerfile runs this in the builder stage and ships the result in the image
# (/usr/share/doc/registry-auth-proxy/); go-ci.yml runs it through scripts/check-image-notices.sh, so a
# notice that cannot be produced fails the build instead of shipping without it.
#
#   scripts/third-party-licenses.sh OUTPUT_FILE
#
# Run from the repository root with the modules downloaded (`go mod download`). CA_COPYRIGHT overrides the
# path of the ca-certificates copyright file (default /usr/share/doc/ca-certificates/copyright).
set -eu

out=${1:?usage: third-party-licenses.sh OUTPUT_FILE}
ca_copyright=${CA_COPYRIGHT:-/usr/share/doc/ca-certificates/copyright}

# Path, version and directory of every non-main module the binary is built from (sorted, unique); empty
# for a standard-library-only module.
mods=$(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}} {{.Dir}}{{end}}{{end}}' ./cmd/server | sort -u)

goroot=$(go env GOROOT)
[ -s "$goroot/LICENSE" ] || { echo "no Go licence file at $goroot/LICENSE" >&2; exit 1; }
[ -s "$ca_copyright" ] || { echo "no CA bundle copyright file at $ca_copyright" >&2; exit 1; }
grep -q 'Mozilla Public License Version 2.0' "$ca_copyright" || { echo "$ca_copyright does not carry the MPL-2.0 text" >&2; exit 1; }

# Licence and notice files of a directory (top level only), one path per line.
notice_files() {
	find "$1" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | sort
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
	echo "Third-party software in the registry-auth-proxy image."
	echo "The service itself is licensed under the 0BSD licence (see LICENSE)."
	echo
	echo "================================================================================"
	echo "Go standard library $(go env GOVERSION)"
	echo "================================================================================"
	echo
	cat "$goroot/LICENSE"
	echo
	echo "================================================================================"
	echo "Mozilla CA certificate bundle (/etc/ssl/certs/ca-certificates.crt), Debian ca-certificates copyright file"
	echo "================================================================================"
	echo
	cat "$ca_copyright"
	if [ -n "$mods" ]; then
		echo "$mods" | while read -r path version dir; do
			files=$(notice_files "$dir")
			if [ -z "$files" ]; then
				echo "no licence file found for $path $version" >&2
				exit 1
			fi
			echo
			echo "================================================================================"
			echo "$path $version"
			echo "================================================================================"
			echo
			echo "$files" | while read -r f; do
				cat "$f"
				echo
			done
		done
	fi
} > "$tmp"

# The file must name every module it covers, and carry real licence text.
if [ -n "$mods" ]; then
	echo "$mods" | while read -r path _; do
		grep -q "^$path " "$tmp" || { echo "$path missing from the notices" >&2; exit 1; }
	done
fi
[ "$(wc -c < "$tmp")" -gt 20000 ] || { echo "notices file is implausibly short" >&2; exit 1; }

cp "$tmp" "$out"
echo "wrote $out: the Go standard library, the CA bundle copyright, $(echo "$mods" | grep -c . || true) third-party modules"
