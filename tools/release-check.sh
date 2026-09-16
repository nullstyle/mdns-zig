#!/bin/sh
# Release hygiene checks (paseto-zig script, with an optional `v` tag prefix).
#
# Usage: tools/release-check.sh [ref-name]
#
# With a ref name (CI passes GITHUB_REF), a tag build additionally requires
# the tag (minus a leading `v`) to equal the version declared in
# build.zig.zon. Without arguments, only the internal consistency check
# runs: the README's documented fetch tag must match the zon version.

set -eu

zon_version=$(sed -n 's/^.*\.version = "\([^"]*\)".*$/\1/p' build.zig.zon | head -n 1)
if [ -z "$zon_version" ]; then
    echo "release-check: could not read .version from build.zig.zon" >&2
    exit 1
fi

readme_tag=$(sed -n 's|.*/archive/refs/tags/v\{0,1\}\([0-9][^/]*\)\.tar\.gz.*|\1|p' README.md | head -n 1)
if [ -z "$readme_tag" ]; then
    echo "release-check: could not read a refs/tags fetch URL from README.md" >&2
    exit 1
fi

if [ "$zon_version" != "$readme_tag" ]; then
    echo "release-check: README pins tag $readme_tag but build.zig.zon declares $zon_version" >&2
    exit 1
fi
echo "release-check: README tag and zon version agree on $zon_version"

if [ "${1:-}" != "" ] && [ "${1#refs/tags/}" != "${1:-}" ]; then
    tag="${1#refs/tags/}"
    tag="${tag#v}"
    if [ "$tag" != "$zon_version" ]; then
        echo "release-check: tag $tag does not match zon version $zon_version" >&2
        exit 1
    fi
    echo "release-check: tag $tag matches zon version"
fi
