# Redoubt Development & Release Workflow

## 1. Versioning

Every stable release must follow the `vA.B.C` format (e.g. `v1.2.3`, `v2.4.3`, `v0.2.19`), following Semantic Versioning principles.

- **Major releases (`A`)**: Introduce breaking changes, significant architectural restructuring, or substantial changes to the application's overall structure.
- **Minor releases (`B`)**: Introduce new features, functionality, or significant improvements while maintaining backward compatibility.
- **Patch releases (`C`)**: Include bug fixes, security fixes, performance improvements, and minor changes that do not introduce breaking changes.

Additional rules:

- The initial stable release is `v1.0.0`.
- Pre-release / non-stable versions must use `-rc.X` identifiers such as `v2.2.0-rc.1`
- Pre-releases must not be treated as stable releases.
- Every stable release must have a corresponding annotated Git tag following the same naming scheme.
- A published release tag must never be moved or reused. Corrections require a new version.

## 2. Release Procedure

All release changes must first be committed and pushed to the `main` branch.

```bash
git status
git add .
git commit -m "..."
git push origin main
```

Verify that the working tree is clean and that the intended commit is present on the remote repository.

### 2.1. Create a Git tag

Create an annotated tag corresponding to the intended release version.

```bash
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3
```

Verify the published tag:

```bash
git ls-remote --tags origin
```

### 2.2. Build artifacts

Every stable release must include at least the following assets:

**Linux x86_64**

- An x86_64 AppImage.
- Build environment: Ubuntu 22.04 (glibc 2.35).
- Python version: 3.12.16 or earlier.
- The resulting artifact must be tested on supported Linux environments.

**Windows x86_64**

- A ZIP archive containing the PyInstaller `--onedir` distribution.
- Build environment: Windows 10 22H2.
- Python version: 3.12.10 or earlier.
- The archive must include `Redoubt.exe` and its corresponding `_internal` directory.
- The resulting executable must be tested on Windows before publication.

Example Windows archive structure:

```text
Redoubt-1.2.3-windows-x86_64.zip
└── redoubt/
    ├── Redoubt.exe
    └── _internal/
        └── ...
```

Build environments and dependency versions must be kept consistent between releases whenever possible.

### 2.3. Release publication

Create the GitHub release using the corresponding Git tag.

```bash
gh release create v1.2.3 \
  Redoubt-1.2.3-x86_64.AppImage \
  Redoubt-1.2.3-windows-x86_64.zip \
  --title "Redoubt v1.2.3" \
  --notes-file RELEASE_NOTES.md
```

Release notes must follow this general structure:

```md
# Redoubt vX.Y.Z

## Security

- Description of security fixes or improvements.

## Improvements

- Description of new features and improvements.

## Compatibility

- Description of compatibility changes and supported environments.
```

Section titles may be adjusted according to the release contents. Only relevant sections should be included.

Release notes must accurately describe the changes introduced by the release. Security fixes should include their impact and affected versions when appropriate.

## 3. Testing

Every release must pass the complete test suite before publication.

Run all tests from the repository root:

```bash
PYTHONPATH=. python -m pytest -v -ra tests/
```

Release requirements:

- No unexpected test failures.
- No unexpected test execution errors.
- No unexplained skipped tests.
- No unexpected `XPASS` results.
- All expected failures and skipped tests must have documented reasons.

A successful test suite is a mandatory release requirement.

### 3.1. Flaky tests

Tests producing inconsistent results across repeated executions must be investigated.

Potential causes include:

- Race conditions.
- Timing-dependent assertions.
- Network latency.
- Resource contention.
- Environment-dependent behavior.
- Incorrect timeout thresholds.

A test passing on a subsequent execution does not invalidate a previous failure.

Flaky tests must be investigated and either fixed or explicitly documented with a justified temporary exception. They must not be silently ignored.

### 3.2. Artifact verification

Passing the Python test suite does not guarantee that packaged applications work correctly.

Every release must also undergo platform-specific verification:

- **Linux**: launch the AppImage and verify core application functionality.
- **Windows**: launch the packaged executable and verify core application functionality.
- Verify that required dependencies are correctly bundled.
- Verify that encrypted storage and cryptographic operations work in the packaged builds.
- Verify that the published SHA-256 checksums match the downloaded artifacts.

## 4. Release Quality Requirements

A release is ready for publication only when all the following conditions are satisfied:

1. All intended changes are committed and pushed to `main`.
2. The release tag points to the correct commit.
3. The complete test suite passes.
4. No unexplained test failures, errors, or skips remain.
5. Linux and Windows artifacts have been successfully built.
6. Both packaged applications have been tested on their respective platforms.
7. Release notes accurately describe the changes.
