# Publishing to PyPI

## Checklist

AuthMCP Gateway is ready for PyPI publication. This document tracks what's needed.

## ✅ Already Done

- [x] `pyproject.toml` configured with all metadata
- [x] Package name: `authmcp-gateway`
- [x] Version: `1.0.0`
- [x] All dependencies specified
- [x] CLI entry point: `authmcp-gateway`
- [x] `MANIFEST.in` for including templates
- [x] MIT License
- [x] README.md with installation instructions
- [x] Package structure in `src/authmcp_gateway/`

## 📋 Before Publishing

- [ ] Test installation in clean environment
- [ ] Verify all templates are included in package
- [ ] Test CLI commands after pip install
- [ ] Decide on versioning strategy (semver)
- [ ] Set up PyPI account credentials

## 🚀 Publishing Steps

### 1. Build Package

```bash
# Install build tools
pip install build twine

# Build distribution packages
python -m build

# This creates:
# - dist/authmcp_gateway-1.0.0-py3-none-any.whl
# - dist/authmcp-gateway-1.0.0.tar.gz
```

### 2. Test on TestPyPI (Optional)

```bash
# Upload to TestPyPI first
python -m twine upload --repository testpypi dist/*

# Test installation
pip install --index-url https://test.pypi.org/simple/ authmcp-gateway
```

### 3. Publish to PyPI

```bash
# Upload to production PyPI
python -m twine upload dist/*

# Verify
pip install authmcp-gateway
```

### 4. Update README

After successful publication, update README.md:

```markdown
### Using pip

```bash
pip install authmcp-gateway
authmcp-gateway init-db
authmcp-gateway start
```
```

### 5. Create Git Tag

```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

## 🔄 Version Bumping

When ready for next release:

1. Update version in `pyproject.toml`
2. Update CHANGELOG (create if needed)
3. Build and publish
4. Create git tag

## 📝 Notes

- PyPI package name: `authmcp-gateway`
- Import name: `authmcp_gateway`
- CLI command: `authmcp-gateway`
- Python >= 3.11 required
- Includes all templates via MANIFEST.in

## 🔗 Resources

- PyPI Project: https://pypi.org/project/authmcp-gateway/ (after publication)
- Test PyPI: https://test.pypi.org/project/authmcp-gateway/
- Packaging Guide: https://packaging.python.org/
