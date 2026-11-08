# Redoubt Development & Release Workflow

This document defines the mandatory development, testing, packaging, validation, and release procedures for Redoubt.

The objective is to ensure that every published release is reproducible, traceable, tested, and consistent with its declared version.

All requirements in this document are mandatory unless explicitly marked otherwise.

---

## 1. Versioning

Every stable release must follow the `vA.B.C` format (e.g. `v1.2.3`, `v2.4.3`, `v3.0.0`), following Semantic Versioning principles.

### 1.1. Version increments

- **Major (`A`)**: Introduces backward-incompatible changes to the application's established compatibility contract, including incompatible architectural or structural changes.
- **Minor (`B`)**: Introduces new functionality or significant improvements while maintaining backward compatibility.
- **Patch (`C`)**: Introduces bug fixes, security fixes, performance improvements, and minor changes without introducing new functionality that warrants a minor release.

Version numbers must never be decreased or reused.

The initial stable release is `v1.0.0`.

### 1.2. Pre-release versions

All candidate releases must use the following format:

`vA.B.C-rc.X`

Examples:
- `v2.2.2-rc.1`
- `v2.2.2-rc.2`
- `v2.2.2-rc.3`

Rules:

- Pre-release identifiers must use monotonically increasing integers.
- Every candidate must have a unique and corresponding Git tag.
- A new candidate must be created whenever changes are introduced after a previous candidate has been published.
- Pre-releases must never be represented or distributed as stable releases.
- A stable release must only be published after a candidate has successfully completed the entire release validation procedure.

### 1.3. Git tag integrity

All release tags must be annotated Git tags.

Once a release tag has been pushed to the remote repository, it must be considered immutable.

The following operations are prohibited:

- Deleting published release tags.
- Moving existing release tags to different commits.
- Reusing previously published version identifiers.
- Force-pushing changes to published release tags.

Corrections must always result in a new version identifier.

Every release tag must reference the exact commit intended for publication.

---

## 2. Development Workflow

All release candidates must originate from the `main` branch.

Before preparing a release:

1. Complete the intended implementation.
2. Run the relevant local tests.
3. Review all changes.
4. Remove temporary files, debugging code, generated artifacts, and unintended modifications.
5. Verify dependency declarations and packaging configuration.
6. Ensure that the repository contains no unintended changes.

### 2.1. Commit requirements

Commits must represent logically distinct changes.

Commit messages must describe their purpose clearly.

Avoid:
- Unrelated changes in the same commit.
- Unnecessary temporary commits on `main`.
- Committing generated files, caches, build directories, or local configuration.
- Amending or rewriting commits that have already been published.

Stage files explicitly whenever practical:

```bash
git status
git add <specific-files>
git diff --cached
git commit -m "..."
git push origin main
```

Before proceeding, verify:

```bash
git status --short
git log -1 --oneline
git ls-remote origin refs/heads/main
```

The working tree must be clean, and the intended commit must be present on the remote repository.

---

## 3. Release Candidate Procedure

Every release must first undergo a release candidate cycle.

A release candidate is a complete, installable build intended for final validation.

### 3.1. Create the candidate tag

Create an annotated tag referencing the intended commit:

```bash
git tag -a v2.2.2-rc.1 -m "Release candidate v2.2.2-rc.1"
git push origin v2.2.2-rc.1
```

Verify the remote tag:

```bash
git ls-remote origin refs/tags/v2.2.2-rc.1
```

The tag must reference the intended commit.

### 3.2. Automated validation

Every pushed release candidate must trigger the release CI/CD workflow.

The workflow must perform, at minimum:

1. Repository and version consistency checks.
2. Python dependency installation.
3. Complete automated test suite execution.
4. Packaging and artifact generation.
5. Artifact structure verification.
6. SHA-256 checksum generation.
7. Release artifact validation.

The workflow must fail if any mandatory step fails.

A failed candidate must not be promoted to stable.

### 3.3. Candidate iteration

If a candidate fails validation:

1. Identify and investigate the failure.
2. Implement the required correction.
3. Commit and push the correction to `main`.
4. Create a new candidate tag.

Example:

```text
v2.2.2-rc.1 → FAILED
v2.2.2-rc.2 → FAILED
v2.2.2-rc.3 → PASSED
```

Previously published candidates must remain unchanged.

A successful candidate must not receive additional code modifications before stable publication.

---

## 4. Testing Requirements

Every release candidate must pass the complete automated test suite.

Run tests from the repository root:

```bash
PYTHONPATH=. python -m pytest -v -ra tests/
```

### 4.1. Test acceptance criteria

A test suite is considered successful only when:

- No unexpected test failures occur.
- No unexpected test execution errors occur.
- No unexplained skipped tests remain.
- No unexpected `XPASS` results occur.
- All expected failures (`XFAIL`) have documented reasons.
- All intentional skips have documented reasons.
- No test has been silently excluded from the release test configuration.

Where possible, use strict XPASS handling:

```ini
[pytest]
xfail_strict = true
```

A successful exit code alone must not replace inspection of the complete test report.

### 4.2. Flaky tests

A flaky test is a test whose outcome changes without a corresponding change in the tested implementation or environment.

Potential causes include:

- Race conditions.
- Timing-dependent assertions.
- Network latency.
- Resource contention.
- Environment-dependent behavior.
- Incorrect timeout thresholds.

Flaky tests must be investigated.

A subsequent successful execution does not invalidate an earlier failure.

Temporary exceptions require:

- Identification of the affected test.
- Documentation of the failure and its suspected cause.
- A justification for the exception.
- A defined remediation plan.

Exceptions must never be used to conceal known failures.

### 4.3. Test reproducibility

Release validation should be performed in a consistent environment.

Where possible:

- Pin dependency versions.
- Use the same Python version across equivalent test environments.
- Record the Python version and operating system used.
- Keep CI and local test configurations consistent.
- Avoid tests that depend on external services without explicit control over their availability.

---

## 5. Build & Packaging Requirements

Every release candidate must produce the following distributable artifacts.

### 5.1. Linux x86_64

Required artifact:

`Redoubt-X.Y.Z-x86_64.AppImage`

Build requirements:

- Build environment: Ubuntu 22.04.
- glibc baseline: 2.35.
- Python: 3.12.16 or earlier.
- Architecture: x86_64.

The resulting AppImage must be tested on supported Linux environments.

### 5.2. Windows x86_64

Required artifact:

`Redoubt-X.Y.Z-windows-x86_64.zip`

Build requirements:

- Build environment: Windows 10 22H2.
- Python: 3.12.10 or earlier.
- Architecture: x86_64.
- Packaging: PyInstaller `--onedir`.

Expected archive structure:

```text
Redoubt-X.Y.Z-windows-x86_64.zip
└── redoubt/
    ├── Redoubt.exe
    └── _internal/
        └── ...
```

The archive must contain all required runtime dependencies.

The executable must be tested on Windows before publication.

### 5.3. Artifact hygiene

Before publication, verify that distributable archives do not contain unintended files.

Examples include:

- `__pycache__/`
- `*.pyc`
- `.pytest_cache/`
- Temporary build files.
- Local configuration files.
- Development-only dependencies.
- Unintended logs or debugging artifacts.

Only files required for the distribution must be included.

---

## 6. Artifact Verification

Passing the Python test suite does not establish that packaged applications work correctly.

Every release candidate must undergo independent artifact verification.

### 6.1. Linux verification

- Confirm that the AppImage exists and is executable.
- Launch the AppImage.
- Verify successful application initialization.
- Verify core application functionality.
- Verify encrypted storage operations.
- Verify cryptographic operations.
- Verify that required runtime dependencies are available.

### 6.2. Windows verification

- Extract the ZIP archive.
- Launch `Redoubt.exe`.
- Verify successful application initialization.
- Verify core application functionality.
- Verify encrypted storage operations.
- Verify cryptographic operations.
- Verify that all required runtime dependencies are bundled.

---

## 7. Stable Release Promotion

A stable release is a promotion of an already validated release candidate.

It must not introduce additional code changes or rebuild the application from a potentially different environment.

### 7.1. Promotion requirements

Before stable publication, verify that:

1. The final release candidate passed the complete CI/CD workflow.
2. All required artifacts were successfully generated.
3. Linux and Windows artifact verification succeeded.
4. All mandatory test requirements were satisfied.
5. Release notes are complete and accurate.
6. The candidate commit is the intended stable release commit.

### 7.2. Stable tag creation

The stable tag must reference the exact same commit as the final validated release candidate.

Example:

```text
v2.2.2-rc.3 ──┐
              ├── Same commit SHA
v2.2.2 ───────┘
```

Create the stable tag:

```bash
git tag -a v2.2.2 -m "Release v2.2.2"
git push origin v2.2.2
```

Verify that both tags reference the same commit.

### 7.3. Stable publication

Only after all promotion requirements have been satisfied may the GitHub stable release be published.

The release must:

- Use the corresponding stable Git tag.
- Include the validated Linux and Windows artifacts.
- Include the final release notes.
- Be marked as a stable release, not a pre-release.

---

## 8. Release Notes

Every release must include accurate and concise release notes.

Recommended structure:

```md
# Redoubt vX.Y.Z

## Security

- Security fixes and improvements.

## Improvements

- New features and significant improvements.

## Bug Fixes

- Corrected issues.

## Compatibility

- Compatibility changes and supported environments.
```

Only relevant sections should be included.

Security-related changes must describe, when appropriate:

- The nature of the vulnerability.
- Its potential impact.
- Affected versions.
- The version containing the correction.

Do not classify every bug as a security vulnerability.

Release notes must describe changes actually introduced by the corresponding release.

---

## 9. CI/CD Integrity

The release CI/CD pipeline is a mandatory component of the release process.

It must validate release candidates and stable tags independently.

### 9.1. Trigger requirements

The release workflow must support:

- Release candidate tag pushes.
- Stable release tag pushes.
- Manual execution for diagnostic purposes.

The workflow must validate that:

- The tag format is correct.
- The tag version matches the project version.
- The tag references the intended commit.
- The repository state is consistent with the release.
- All mandatory tests and build operations complete successfully.

### 9.2. Failure handling

If a mandatory CI/CD job fails:

- The release must be considered unvalidated.
- The failure must be investigated.
- The affected candidate must not be promoted.
- A corrected candidate must be created when source changes are required.

A green CI status must correspond to the exact commit and artifacts intended for publication.

---

## 10. Final Release Checklist

A release is authorized for stable publication only when every mandatory requirement below has been satisfied.

### Source integrity

- [ ] All intended changes are committed and pushed to `main`.
- [ ] The working tree is clean.
- [ ] The release tag references the intended commit.
- [ ] The published tag is immutable.
- [ ] The project version matches the release tag.

### Automated validation

- [ ] Complete test suite passes.
- [ ] No unexplained failures or execution errors remain.
- [ ] No unexplained skips or unexpected XPASS results remain.
- [ ] Expected failures are documented.
- [ ] CI/CD validation succeeds for the exact candidate commit.

### Packaging

- [ ] Linux AppImage successfully built.
- [ ] Windows ZIP distribution successfully built.
- [ ] Correct architecture and runtime dependencies verified.
- [ ] No unintended files or generated artifacts included.
- [ ] Build environments and versions recorded.

### Artifact verification

- [ ] Linux application successfully launched and tested.
- [ ] Windows application successfully launched and tested.
- [ ] Core functionality verified on both platforms.
- [ ] Encrypted storage and cryptographic operations verified.

### Stable publication

- [ ] Final candidate has passed all mandatory validation.
- [ ] Stable tag references the exact final candidate commit.
- [ ] Stable artifacts are identical to the validated candidate artifacts.
- [ ] Release notes accurately describe the changes.
- [ ] Stable release assets and checksums are present.
- [ ] GitHub release is correctly marked as stable.

**A single unchecked mandatory requirement means the release is not ready for stable publication.**
