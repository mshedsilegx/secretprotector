# Testing Strategy: SecretProtector

This document describes the testing architecture, coverage, and execution procedures for the SecretProtector project.

## 1. Architecture of the Test Suite

The test suite is designed for **high-impact instrumentation** and **comprehensive mocking**, enabling a statement coverage goal of >90% while maintaining fast execution cycles.

*   **Unit Tests (`pkg/libsecsecrets`):** Focus on cryptographic integrity and security boundary enforcement. It uses internal variable exporting (e.g., `RandReader`, `OsStat`) to allow cross-package mocking of OS behaviors and CSPRNG failures.
*   **Integration Tests (`cmd/secretprotector`):** Focus on CLI behavior, flag parsing, and end-to-end data flows. The `main` package is refactored into a `runMain()` function to allow testing without process termination.
*   **Cross-Platform Simulation:** The suite includes logic to mock `RuntimeGOOS`, allowing Windows-specific and Linux-specific security checks to be verified on any host OS.

## 2. Technical Requirements and Setup

*   **Go Version:** 1.21+
*   **Dependencies:** Standard Go library only (no external mocking frameworks).
*   **Environment Variables:**
    *   `SECRETPROTECTOR_MASTER_KEY`: Used to test environment-based key resolution.
    *   `TEMP` (Windows) / `TMPDIR` (Linux): Used for coverage profile storage.
*   **Constraints:** Tests must not create permanent files in the repository; all temporary objects are created in the system's temp directory.

## 3. List of Tests

| Logical Group | Test Name | Technical Purpose | Success Criteria |
| :--- | :--- | :--- | :--- |
| **Cryptography** | `TestGenerateKey` | Verify CSPRNG output and sync.Pool stability. | Valid 64-char hex, pool reuse success. |
| **Cryptography** | `TestEncryptDecrypt` | Verify AES-256-GCM round-trip with Context. | Plaintext matches original. |
| **Key Resolution** | `TestResolveKeyPrecedence` | Verify Flag > Env > File hierarchy and empty fallbacks. | Correct key selected based on priority. |
| **Key Resolution** | `TestResolveKeyFileVariants` | Verify loading 64-char hex and 32-byte raw keys from files. | Successful resolution of both formats. |
| **Security** | `TestInsecureFilePermissions` | Verify OS-specific path/mode blocks. | Correct custom security error returned. |
| **Error Handling** | `TestErrors` | Verify library resilience and custom error types. | Proper error wrapping and type detection. |
| **CLI Integration** | `TestMainCLI` | Verify flags (-version, -generate) and default Usage. | Correct output format and usage instructions. |
| **CLI Integration** | `TestCLIEncryptionDecryption` | End-to-end flow using all key source flags. | Transformations match transformed library output. |
| **CLI Integration** | `TestCLIErrorPaths` | Verify CLI handling of invalid/insecure inputs. | Meaningful error messages written to Stderr. |
| **CLI Integration** | `TestCLIGenerateError` | Verify CLI behavior when entropy is exhausted. | Graceful failure message on Stderr. |

## 4. Code Coverage Report

| Package | Statement Coverage | Goal | Status |
| :--- | :--- | :--- | :--- |
| `pkg/libsecsecrets` | **94.9%** | >90% | **PASSED** |
| `cmd/secretprotector` | **93.9%** | >90% | **PASSED** |
| **Total Project** | **~94.4%** | >90% | **PASSED** |

## 5. Realistic Data Simulation

The test suite simulates real-world failure modes:
*   **Entropy Exhaustion:** Mocks `RandReader` with an empty reader to simulate CSPRNG failures.
*   **File System Errors:** Mocks `OsStat` and `OsReadFile` to simulate permission denied or file not found errors.
*   **OS Environment:** Mocks `RuntimeGOOS` to simulate Windows vs. Linux security logic (e.g., checking for `C:\Users\Public` vs. Unix file modes).

## 6. How to Run the Tests

### Windows (PowerShell)
```powershell
# Run library tests with coverage
go test -v -coverprofile="$env:TEMP\libsecsecrets.cov" ./pkg/libsecsecrets; if ($?) { go tool cover -func="$env:TEMP\libsecsecrets.cov" }

# Run CLI tests with coverage
go test -v -coverprofile="$env:TEMP\secretprotector.cov" ./cmd/secretprotector; if ($?) { go tool cover -func="$env:TEMP\secretprotector.cov" }
```

### Linux (Bash)
```bash
# Run library tests with coverage
go test -v -coverprofile="${TEMP}/libsecsecrets.cov" ./pkg/libsecsecrets && go tool cover -func="${TEMP}/libsecsecrets.cov"

# Run CLI tests with coverage
go test -v -coverprofile="${TEMP}/secretprotector.cov" ./cmd/secretprotector && go tool cover -func="${TEMP}/secretprotector.cov"
```

## 7. Maintenance and Troubleshooting

*   **Lint Errors:** Ensure `go fmt ./...` and `go vet ./...` are run before testing.
*   **Coverage Drops:** If adding new logic to `ResolveKey` or `validateFilePermissions`, update the corresponding mock logic in `libsecsecrets_test.go`.
*   **Test Failures on Windows:** If `TestInsecureFilePermissions` fails, verify that the `RuntimeGOOS` mock is correctly active, as Windows handles file modes differently than Linux.
