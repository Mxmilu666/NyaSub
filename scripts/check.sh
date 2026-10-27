#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

echo "==> Go tests"
(cd backend && go test ./...)

echo "==> Frontend typecheck"
(cd web && npm run typecheck)

echo "==> Frontend production build"
(cd web && npm run generate)

echo "All checks passed."
