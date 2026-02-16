#!/bin/sh
set -e

cd "$(dirname "$0")/.."

echo "==> Rebuilding Tailwind CSS..."
tailwindcss -i src/authmcp_gateway/static/input.css \
    -o src/authmcp_gateway/static/tailwind.css --minify

echo "==> Building package..."
rm -rf dist/ build/
python -m build --no-isolation

echo "==> Uploading to PyPI..."
twine upload dist/authmcp_gateway-*

echo "==> Done!"
