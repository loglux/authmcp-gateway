# Release Process

This project uses a repeatable release flow to keep PyPI, git tags, containers, and footer metadata in sync.

## 1. Preconditions

- Working tree is clean: `git status -sb`
- On `main` (or release branch that will be merged to `main`)
- Tests pass:
  - `./venv/bin/pytest -q`

## 2. Bump Version

Update both files to the same version:

- `pyproject.toml`
- `src/authmcp_gateway/__init__.py`

Example: `1.2.19 -> 1.2.20`

## 3. Commit And Push

```bash
git add pyproject.toml src/authmcp_gateway/__init__.py
git commit -m "Bump version to 1.2.20"
git push
```

If the release contains code changes, include those files in the same release commit.

## 4. Build Artifacts

```bash
./venv/bin/python -m build --no-isolation
```

Expected output in `dist/`:

- `authmcp_gateway-<version>.tar.gz`
- `authmcp_gateway-<version>-py3-none-any.whl`

## 5. Publish To PyPI

```bash
./venv/bin/python -m twine upload dist/authmcp_gateway-<version>*
```

Notes:

- If `twine` is missing: `./venv/bin/pip install twine`
- Verify release page exists on PyPI after upload.

## 6. Tag Release

```bash
git tag v<version>
git push --tags
```

## 7. Rebuild/Restart Container With Commit Hash

Footer shows `vX.Y.Z (commit)` only if `GIT_COMMIT` is injected at build/start time.

```bash
GIT_COMMIT=$(git rev-parse --short HEAD) docker compose build
GIT_COMMIT=$(git rev-parse --short HEAD) docker compose up -d
```

## 8. Post-Release Verification

Service health:

```bash
curl -i http://localhost:9105/health
```

Container runtime metadata:

```bash
docker exec authmcp-gateway sh -lc 'echo GIT_COMMIT=$GIT_COMMIT; python - <<\"PY\"\nfrom authmcp_gateway import __version__\nprint(__version__)\nPY'
```

Expected:

- Health endpoint returns `200`
- App version equals released version
- `GIT_COMMIT` equals current short git hash

## Optional Shortcut Script

There is a helper script at `scripts/publish.sh` for build/upload/tag steps.
It does **not** handle container rebuild/restart with explicit `GIT_COMMIT`, so still run Step 7.
