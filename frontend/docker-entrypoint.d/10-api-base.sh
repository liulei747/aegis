#!/bin/sh
# Write the runtime configuration before nginx starts.
#
# The nginx image runs every `/docker-entrypoint.d/*.sh` before it serves anything, so the file
# exists by the time a browser can ask for it. This is the whole reason the same image can be
# deployed against several gateways: `AEGIS_API_BASE` is read here, not at build time.
#
# An empty value is written as-is and means "same origin" -- correct only if something in front
# of this container forwards `/v1`, which this image does not do itself.
set -eu

base="${AEGIS_API_BASE:-}"

# The value is interpolated into JavaScript, so a quote or a newline in it would produce a
# broken file that fails in the browser with no explanation. Refuse instead of guessing.
case "$base" in
  *'"'*|*"'"*|*'
'*)
    echo "AEGIS_API_BASE contains a quote or a newline, which cannot be written safely" >&2
    exit 1
    ;;
esac

target=/usr/share/nginx/html/config.js
printf 'window.__AEGIS_CONFIG__ = { apiBase: "%s" };\n' "$base" > "$target"
echo "aegis frontend: api base = ${base:-<same origin>}"
