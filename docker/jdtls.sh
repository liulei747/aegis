#!/bin/sh
# jdt.ls launcher: what the eclipse tarball leaves for us to do.
#
# Two things the unpacked snapshot does not handle, and both fail in ways that look like
# something else:
#
#   1. **A writable configuration area.** jdt.ls writes OSGi state into `-configuration`, and
#      the image's copy under /opt/jdtls belongs to root while the container runs as `aegis`.
#      Eclipse's launcher then exits with "Invalid Configuration Location ... is not writable",
#      which reads like a missing path and is not one. So the pristine copy is duplicated to a
#      writable location on first use; the image's copy stays untouched, so two workspaces
#      cannot fight over one state directory.
#   2. **A data directory** (`-data`), which otherwise defaults to a location under the install
#      directory and hits the same ownership problem.
#
# The JVM flags are jdt.ls's documented ones (`eclipse.application`, the default start level,
# `--add-opens` for the reflection it needs on JDK 17+), not cargo cult: without the
# `--add-modules=ALL-SYSTEM` and the `--add-opens` pair the server starts and then fails to
# index, which surfaces as an empty call graph rather than as an error.
set -eu

config="${JDTLS_CONFIG_DIR:-${TMPDIR:-/tmp}/jdtls-config}"
data="${JDTLS_DATA_DIR:-${TMPDIR:-/tmp}/jdtls-data}"

if [ ! -d "$config" ]; then
  mkdir -p "$(dirname "$config")"
  cp -r /opt/jdtls/config_linux "$config"
fi
mkdir -p "$data"

# The launcher jar's name carries its version, so the glob must stay unquoted.
exec java \
  -Declipse.application=org.eclipse.jdt.ls.core.id1 \
  -Dosgi.bundles.defaultStartLevel=4 \
  -Declipse.product=org.eclipse.jdt.ls.core.product \
  -Xmx1G \
  --add-modules=ALL-SYSTEM \
  --add-opens java.base/java.util=ALL-UNNAMED \
  --add-opens java.base/java.lang=ALL-UNNAMED \
  -jar /opt/jdtls/plugins/org.eclipse.equinox.launcher_*.jar \
  -configuration "$config" \
  -data "$data" \
  "$@"
