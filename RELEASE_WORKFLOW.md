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

## 7. Stable Release Preparation & Promotion

A stable release must be built from a dedicated stable-version commit.

The final validated release candidate and the stable release must have different version identifiers in the project metadata. Therefore, the stable tag must not reference the release candidate commit.

The release candidate validates the application at its candidate version. After successful validation, a separate commit must remove the pre-release suffix from all project version references.

### 7.1. Stable version preparation

After the final release candidate has passed all mandatory validation:

1. Update every project version reference from `X.Y.Z-rc.N` to `X.Y.Z`.
2. Verify that no release-candidate suffix remains in application or packaging version metadata.
3. Update the release notes for the stable release, describing changes since the previous stable release.
4. Review the complete diff and verify that the only source changes are those required to prepare the stable version.
5. Commit and push the stable-version changes to `main`.

Example:

```text
Validated candidate: v2.3.0-rc.2
Project version:     2.3.0-rc.2

Stable preparation commit:
Project version:     2.3.0
```

The stable preparation commit must not introduce application functionality changes, bug fixes, dependency changes, or build-configuration changes. If any such changes are necessary, a new release candidate must be created and fully validated first.

### 7.2. Stable tag creation

Create a new annotated stable tag pointing to the stable-version preparation commit:

```bash
git tag -a v2.3.0 -m "Release v2.3.0"
git push origin v2.3.0
```

The stable tag must reference the commit containing the stable version metadata (`X.Y.Z`), not the preceding release candidate commit (`X.Y.Z-rc.N`).

Verify the tag and project version:

```bash
git show v2.3.0:pyproject.toml
git show v2.3.0:redoubt/__init__.py
git rev-parse v2.3.0^{commit}
```

The stable tag must be immutable once pushed.

### 7.3. Stable build and publication

Pushing the stable tag must immediately trigger the stable release CI/CD workflow.

The workflow must independently:

- Verify that the tag version matches all project version references.
- Run the complete automated test suite.
- Build the Linux and Windows stable artifacts using the required build environments.
- Generate SHA-256 checksums.
- Validate the generated artifacts.
- Create the GitHub stable Release and upload the artifacts, checksums, and release notes after all mandatory jobs succeed.

Stable artifacts must be built from the exact commit referenced by the stable tag. They must not be relabelled or reused from the release candidate, because the candidate and stable builds have different embedded version identifiers.

No commits or source modifications may be introduced between stable tag creation and GitHub Release publication. If the stable workflow fails because source changes are required, prepare and validate a new release candidate; do not move or recreate the published stable tag.

The GitHub Release must:

- Use the corresponding stable Git tag.
- Include the stable Linux and Windows artifacts.
- Include the final release notes and SHA-256 checksums.
- Be marked as a stable release, not a pre-release.

---

## 8. GitHub Release Publication

GitHub Releases are the official distribution mechanism for Redoubt binaries and release documentation.

A GitHub Release must be created automatically by the release CI/CD workflow after the corresponding tag has passed all required validation procedures. Tag creation triggers the workflow; publication occurs immediately after all mandatory jobs succeed.

### 8.1. Release creation

Create the GitHub Release using the GitHub CLI (`gh`).

The release workflow must create the GitHub Release after successful validation. The following commands illustrate the equivalent manual operation for diagnostic or recovery purposes; they are not a substitute for the automated workflow.

Stable release:

```bash
gh release create v2.3.0 \
  Redoubt-2.3.0-x86_64.AppImage \
  Redoubt-2.3.0-windows-x86_64.zip \
  SHA256SUMS \
  --title "Redoubt 2.3.0" \
  --notes-file RELEASE_NOTES.md
```

Release candidate:

```bash
gh release create v2.3.0-rc.2 \
  Redoubt-2.3.0-rc.2-x86_64.AppImage \
  Redoubt-2.3.0-rc.2-windows-x86_64.zip \
  SHA256SUMS \
  --title "Redoubt 2.3.0-rc.2" \
  --notes-file RELEASE_NOTES.md \
  --prerelease
```

### 8.2. Publication requirements

Every GitHub Release must:

- Reference the corresponding existing Git tag.
- Use the correct version in its title.
- Include the Linux AppImage.
- Include the Windows ZIP distribution.
- Include accurate release notes.
- Include SHA-256 checksums for all distributable artifacts.

Release candidates must be explicitly marked as pre-releases using `--prerelease`.

Stable releases must not use the `--prerelease` flag.

The CI/CD workflow must have the permissions required to publish releases (including `contents: write`). The workflow must not publish a GitHub Release if any mandatory validation or build job fails.

## 8.3. Release Notes

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

## 10.1. Release candidate tag checklist

A release candidate tag may be created only when every requirement below is satisfied:

- [ ] All intended application and build changes are committed and pushed to `main`.
- [ ] The working tree is clean.
- [ ] All project version references contain the intended `X.Y.Z-rc.N` version.
- [ ] Release notes for the candidate are prepared.
- [ ] All required release assets can be built from the tagged commit.

Only after these checks and the required builds are complete may the release candidate tag be created.

Creating the tag immediately triggers the release candidate CI/CD workflow. No commits or source modifications may be introduced after the tag is created.

## 10.2. Release candidate validation checklist

A release candidate is considered validated only when every mandatory requirement below is satisfied:

- [ ] Complete automated test suite passes.
- [ ] Linux AppImage successfully built, launched, and tested.
- [ ] Windows ZIP distribution successfully built, launched, and tested.
- [ ] Core functionality verified on both platforms.
- [ ] Encrypted storage and cryptographic operations verified.
- [ ] Correct architecture and runtime dependencies verified.
- [ ] No unintended files or generated artifacts included.
- [ ] Build environments and versions recorded.
- [ ] CI/CD validation succeeds for the exact candidate tag and commit.

## 10.3. Stable release checklist

A stable release may be published only when every mandatory requirement below is satisfied:

- [ ] Final `vX.Y.Z-rc.N` candidate has passed all mandatory validation.
- [ ] All project version references have been changed from `X.Y.Z-rc.N` to `X.Y.Z`.
- [ ] The stable-version preparation commit contains no application functionality, dependency, or build-configuration changes.
- [ ] Stable release notes accurately describe changes since the latest stable release.
- [ ] The working tree is clean and the stable preparation commit is pushed to `main`.
- [ ] Stable tag `vX.Y.Z` references the stable-version preparation commit, not the RC commit.
- [ ] Stable tag version matches all project version references.
- [ ] Stable CI/CD workflow passes all mandatory validation and build jobs.
- [ ] Stable Linux and Windows artifacts are built from the exact stable tag commit.
- [ ] Stable artifacts contain the stable `X.Y.Z` version, without an RC suffix.
- [ ] GitHub Release is created automatically after successful validation.
- [ ] GitHub Release is correctly marked as stable, not pre-release.
- [ ] Published assets, checksums, tag, and release notes are verified.

No commits or source modifications may occur between stable tag creation and GitHub Release publication. If source changes are required after tagging, the tag must not be moved or reused; the release process must be restarted with a new valid version identifier.
