#!/bin/sh
set -e

cd "$(dirname "$0")/.."

# Extract version from pyproject.toml
VERSION=$(grep '^version' pyproject.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
echo "==> Publishing v${VERSION}"

echo "==> Rebuilding Tailwind CSS..."
tailwindcss -i src/authmcp_gateway/static/input.css \
    -o src/authmcp_gateway/static/tailwind.css --minify

echo "==> Building package..."
rm -rf dist/ build/
python -m build --no-isolation

echo "==> Uploading to PyPI..."
twine upload dist/authmcp_gateway-*

echo "==> Creating git tag v${VERSION}..."
git tag "v${VERSION}" 2>/dev/null && git push --tags || echo "    Tag v${VERSION} already exists, skipping"

echo "==> Done! Published v${VERSION}"
