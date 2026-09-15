#!/usr/bin/env bash
set -euo pipefail

GRADLE_VERSION="9.7.0"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if command -v gradle >/dev/null 2>&1; then
  GRADLE_CMD="$(command -v gradle)"
elif [[ -x "$HOME/gradle-${GRADLE_VERSION}/bin/gradle" ]]; then
  GRADLE_CMD="$HOME/gradle-${GRADLE_VERSION}/bin/gradle"
else
  echo "Gradle ${GRADLE_VERSION} is required to generate the wrapper." >&2
  exit 1
fi

cd "$ROOT"
"$GRADLE_CMD" wrapper --gradle-version "$GRADLE_VERSION" --distribution-type bin

CHECKSUM_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-wrapper.jar.sha256"
EXPECTED="$(curl --fail --location --silent --show-error "$CHECKSUM_URL")"
ACTUAL="$(sha256sum gradle/wrapper/gradle-wrapper.jar | awk '{print $1}')"

if [[ "$EXPECTED" != "$ACTUAL" ]]; then
  echo "Wrapper JAR checksum mismatch" >&2
  echo "expected: $EXPECTED" >&2
  echo "actual:   $ACTUAL" >&2
  exit 1
fi

chmod +x gradlew

echo "Gradle wrapper generated and verified: $GRADLE_VERSION"
echo "Commit gradlew, gradlew.bat, gradle/wrapper/gradle-wrapper.jar, and gradle/wrapper/gradle-wrapper.properties."
