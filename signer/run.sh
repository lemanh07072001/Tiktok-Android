#!/bin/bash
set -e
cd "$(dirname "$0")"
export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21}"
[ -x "$JAVA_HOME/bin/java" ] || JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null)"
[ -x "$JAVA_HOME/bin/java" ] || { echo "JDK21 not found (brew install openjdk@21)"; exit 1; }
export PATH="$JAVA_HOME/bin:$PATH"
GRADLE="${GRADLE:-$PWD/tools/gradle/bin/gradle}"
[ -x "$GRADLE" ] || GRADLE="$(command -v gradle || true)"
echo "[*] JAVA_HOME=$JAVA_HOME  gradle=$GRADLE"
"$GRADLE" -q run
