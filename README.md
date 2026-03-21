# SecretProtector

SecretProtector is a professional-grade password obfuscation system for Go. It ensures that sensitive credentials (such as SFTP passwords, API keys, or database strings) are never stored in plaintext on disk or in version control by using AES-256-GCM authenticated encryption and a multi-source master key resolution strategy.

## Objectives
- **Zero Plaintext Storage:** Eliminate plaintext secrets from configuration files and environment variables.
- **Synchronized Logic:** Use a shared library (`pkg/libsecsecrets`) to ensure the CLI and Application always use the same cryptographic standards.
- **Flexible Key Management:** Support master keys from direct input, environment variables, or protected files.
- **Platform Security:** Enforce OS-level security boundaries (Linux permissions and Windows location checks).

## Command Line Arguments

The `secretprotector` CLI utility provides the following flags:

| Flag | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-version` | bool | `false` | Print the version information and exit. |
| `-generate` | bool | `false` | Generate a new 32-byte Master Key (64-char hex string). |
| `-encrypt` | string | `""` | The plaintext string to obfuscate. |
| `-decrypt` | string | `""` | The Base64-encoded ciphertext to decrypt. |
| `-key` | string | `""` | Provide the Master Key directly (64-char hex or 32-byte raw). |
| `-key-env` | string | `SECRETPROTECTOR_MASTER_KEY` | The name of the environment variable containing the Master Key. |
| `-key-file` | string | `""` | The fully qualified path to a file containing the Master Key. |

## CLI Usage Examples

### 1. Building from Source
Build the application with optimized settings for security and size.
```powershell
# Get the version from version.txt
$version = Get-Content version.txt -Raw

# Build the application
go build -buildvcs=false -ldflags "-s -w -X main.version=$version -trimpath" -buildmode=pie -o $env:TEMP/ ./cmd/secretprotector
```

### 2. Initial Setup: Generate a Master Key
Generate a new secure key for your environment.
```powershell
go run ./cmd/secretprotector -generate
# Output: 4f7e2d... (64 character hex string)
```

### 3. Obfuscate a Secret (Direct Key)
Encrypt a secret (e.g., an SFTP password) by providing the key directly on the command line.
```powershell
go run ./cmd/secretprotector -key "YOUR_HEX_KEY" -encrypt "your_secret_here"
# Output: Base64 string (nonce + ciphertext)
```

### 4. Obfuscate a Secret (Environment Variable)
The most common way to use the CLI in a dev environment.
```powershell
# Set the environment variable
$env:SECRETPROTECTOR_MASTER_KEY = "YOUR_HEX_KEY"

# Encrypt without passing the key flag
go run ./cmd/secretprotector -encrypt "your_secret_here"
```

### 5. Decrypt a Secret (Key File)
Useful for verifying secrets on a production server where the key is stored in a protected file.
```powershell
# Linux example (assuming /etc/secrets/key.txt has 0400 permissions)
./secretprotector -key-file "/etc/secrets/key.txt" -decrypt "A1B2C3D4..."
```

## Library Integration
To integrate SecretProtector into your own Go application, please refer to the [SAMPLEAPP.md](./SAMPLEAPP.md) guide. It details the "Bootstrap Sequence" required to resolve keys and decrypt secrets at runtime securely.

## Architecture
For details on design choices, cryptographic standards, and project structure, see [ARCHITECTURE.md](./ARCHITECTURE.md).
