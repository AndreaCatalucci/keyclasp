#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf '%s\n' "Usage: assert-exact-release-source.sh <tag>" >&2
    exit 2
fi

tag=$1
if ! printf '%s\n' "$tag" | /usr/bin/grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$'; then
    printf '%s\n' "Tag has an invalid release format: $tag" >&2
    exit 2
fi
if ! git show-ref --verify --quiet "refs/tags/$tag"; then
    printf '%s\n' "Release source is not an exact tag: $tag" >&2
    exit 1
fi

head_commit=$(git rev-parse HEAD)
tag_commit=$(git rev-parse "refs/tags/$tag^{}")
if [ "$tag_commit" != "$head_commit" ]; then
    printf '%s\n' "Tag $tag does not identify the checked-out commit." >&2
    exit 1
fi
if [ -n "$(git status --porcelain)" ]; then
    printf '%s\n' "Release packaging requires a clean worktree." >&2
    exit 1
fi
