#!/bin/sh
# Rebuild Tailwind CSS at startup (handles volume-mounted src overriding image build)
if [ -f /usr/local/bin/tailwindcss ] && [ -f tailwind.config.js ]; then
    tailwindcss -i src/authmcp_gateway/static/input.css \
        -o src/authmcp_gateway/static/tailwind.css --minify 2>&1 | tail -1
fi

exec "$@"
