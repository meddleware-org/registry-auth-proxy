#!/bin/sh
# Builds the image and checks that it ships the licence notices of what it redistributes:
# /usr/share/doc/registry-auth-proxy/{LICENSE,THIRD_PARTY_LICENSES}, with the text of the Go standard library,
# the Mozilla CA bundle's copyright file and every module in the build graph. CI runs it (go-ci.yml, job
# "image"), so the release gate does too.
#
#   scripts/check-image-notices.sh            # uses docker; CONTAINER_CLI=podman for rootless podman
set -eu

cli=${CONTAINER_CLI:-docker}
tag=registry-auth-proxy-notices-check:$$
work=$(mktemp -d)
cid=
cleanup() {
	[ -z "$cid" ] || "$cli" rm -f "$cid" >/dev/null 2>&1 || true
	"$cli" rmi -f "$tag" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

"$cli" build -t "$tag" .
# The image is `scratch` (no shell): create a container without starting it and copy the files out.
cid=$("$cli" create "$tag" /auth-proxy)
for f in LICENSE THIRD_PARTY_LICENSES; do
	"$cli" cp "$cid:/usr/share/doc/registry-auth-proxy/$f" "$work/$f"
	[ -s "$work/$f" ] || { echo "image lacks a non-empty /usr/share/doc/registry-auth-proxy/$f" >&2; exit 1; }
done

# Every module in the module graph must be named, plus the standard library and the CA bundle.
for mod in $(go list -m -f '{{if not .Main}}{{.Path}}{{end}}' all); do
	grep -q "^$mod " "$work/THIRD_PARTY_LICENSES" || { echo "image notices do not cover $mod" >&2; exit 1; }
done
grep -q '^Go standard library ' "$work/THIRD_PARTY_LICENSES" || { echo "image notices do not cover the Go standard library" >&2; exit 1; }
grep -q 'Redistribution and use in source and binary forms' "$work/THIRD_PARTY_LICENSES" || { echo "BSD licence text missing" >&2; exit 1; }
grep -q '^Mozilla CA certificate bundle' "$work/THIRD_PARTY_LICENSES" || { echo "image notices do not cover the CA bundle" >&2; exit 1; }
grep -q 'Mozilla Public License Version 2.0' "$work/THIRD_PARTY_LICENSES" || { echo "MPL-2.0 licence text missing" >&2; exit 1; }
cmp -s LICENSE "$work/LICENSE" || { echo "image LICENSE differs from the repository LICENSE" >&2; exit 1; }
echo "image notices OK"
