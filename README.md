# SecretProtector

SecretProtector is a password obfuscation system for Go. It ensures that sensitive credentials (such as SFTP passwords, API keys, or database strings) are never stored in plaintext on disk or in version control by using AES-256-GCM authenticated encryption and a multi-source master key resolution strategy.

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

**Key Resolution Precedence:**
If multiple key sources are provided, the application resolves them in the following order:
1. **Direct Key (`-key`)**: Highest precedence.
2. **Environment Variable (`-key-env`)**: Used if `-key` is not provided.
3. **Key File (`-key-file`)**: Lowest precedence; used only if no key is found in the other sources.

## CLI Usage Examples

### 1. Building from Source
Build the application with optimized settings for security and size.

**Windows (PowerShell):**
```powershell
# Get the version from version.txt
$version = Get-Content version.txt -Raw

# Build the application
go build -buildvcs=false -ldflags "-s -w -X main.version=$version -trimpath" -buildmode=pie -o $env:TEMP/ ./cmd/secretprotector
```

**Linux/Unix (Bash):**
```bash
# Get the version from version.txt and build the application
go build -buildvcs=false -ldflags "-s -w -X main.version=$(cat version.txt) -trimpath" -buildmode=pie -o ./secretprotector ./cmd/secretprotector
```

### 2. Initial Setup: Generate a Master Key
Generate a new secure key for your environment.

**Windows (PowerShell) or Linux/Unix (Bash):**
```powershell
go run ./cmd/secretprotector -generate
# Output: 4f7e2d... (64 character hex string)
```

### 3. Obfuscate a Secret (Direct Key: `-key`)
Encrypt a secret (e.g., an SFTP password) by providing the key directly on the command line. This is useful for testing or one-off operations but is less secure than other methods because the key may be visible in process listings or shell history.

**Windows (PowerShell) or Linux/Unix (Bash):**
```powershell
# Use a 64-character hex string as the key - Output: Base64 string (nonce + ciphertext)
go run ./cmd/secretprotector -key "4f7e2d9a3b1c...64chars" -encrypt "your_secret_here"

# The -key flag also supports a 32-character raw string (less common)
go run ./cmd/secretprotector -key "a_32_character_long_secret_str!!" -encrypt "your_secret_here"
```

### 4. Obfuscate a Secret (Environment Variable: `-key-env`)
The recommended way for automated environments. By default, it looks for `SECRETPROTECTOR_MASTER_KEY`.

**Windows Note:** The master key environment variable can be stored in either the **USER** or **SYSTEM** scope. The application retrieves the value from the process environment block, 
where User variables take precedence over System variables.

To ensure variables persist after a server reboot, use the `setx` command:
- **User Scope:** `setx SECRETPROTECTOR_MASTER_KEY "your_hex_key"`
- **System Scope:** `setx SECRETPROTECTOR_MASTER_KEY "your_hex_key" /M` (requires Administrative privileges)

*Note: `setx` updates the registry; you must open a new terminal window for the changes to take effect in your current session.*

#### 4.1 Set the environment variable (default name) with a 64-character hex string
**Windows (PowerShell):**
```powershell
# Set for current session only
$env:SECRETPROTECTOR_MASTER_KEY = "4f7e2d9a3b1c...64chars"
$env:MY_APP_KEY = "4f7e2d9a3b1c...64chars"

# Set permanently (User scope)
setx SECRETPROTECTOR_MASTER_KEY "4f7e2d9a3b1c...64chars"
setx MY_APP_KEY "4f7e2d9a3b1c...64chars"

# Set permanently (System scope - Run as Admin)
setx SECRETPROTECTOR_MASTER_KEY "4f7e2d9a3b1c...64chars" /M
setx MY_APP_KEY "4f7e2d9a3b1c...64chars" /M
```

**Linux/Unix (Bash):**
```bash
# Set for current session
export SECRETPROTECTOR_MASTER_KEY="4f7e2d9a3b1c...64chars"
export MY_APP_KEY="4f7e2d9a3b1c...64chars"

# To set permanently, add the above lines to your ~/.bashrc or ~/.profile
```

#### 4.2 Encrypt using the default environment variable or a custom environment variable name
```powershell
# Using default (SECRETPROTECTOR_MASTER_KEY)
go run ./cmd/secretprotector -encrypt "your_secret_here"

# Using custom environment variable
go run ./cmd/secretprotector -key-env "MY_APP_KEY" -encrypt "your_secret_here"
```

### 5. Obfuscate a Secret (Key File: `-key-file`)
The most secure way to manage keys. The file must have restricted permissions. 

**Important:** You **must** use absolute paths for the `-key-file` flag. Relative paths are disallowed to prevent path traversal attacks and ensure the application always references the intended secure location.

**Security Requirements:**
- **Windows:** Files cannot be in "Public" or "Temp" directories.
- **Linux/Unix:** Files must have owner-only permissions (e.g., `0400` or `0600`).

**Windows (PowerShell):**
```powershell
# Encrypt using a key stored in a file
go run ./cmd/secretprotector -key-file "C:\Users\Admin\Documents\master.key" -encrypt "your_secret_here"
```

**Linux/Unix (Bash):**
```bash
# Ensure secure permissions first
chmod 0400 /etc/secrets/master.key

# Encrypt using the key file
go run ./cmd/secretprotector -key-file "/etc/secrets/master.key" -encrypt "your_secret_here"
```

### 6. Decrypt a Secret
Decryption requires the same master key used for encryption. Examples are shown by key source.

#### 6.1 Direct Key (`-key`)
**Windows (PowerShell) or Linux/Unix (Bash):**
```bash
go run ./cmd/secretprotector -key "4f7e2d9a3b1c...64chars" -decrypt "A1B2C3D4..."
```

#### 6.2 Environment Variable (`-key-env`)
Refer to [Section 4.1](#41-set-the-environment-variable-default-name-with-a-64-character-hex-string) for instructions on how to set these variables for Windows and Linux.

**Windows (PowerShell) or Linux/Unix (Bash):**
```bash
# Using the default environment variable (SECRETPROTECTOR_MASTER_KEY)
go run ./cmd/secretprotector -decrypt "A1B2C3D4..."

# Using a custom environment variable name
go run ./cmd/secretprotector -key-env "MY_APP_KEY" -decrypt "A1B2C3D4..."
```

#### 6.3 Key File (`-key-file`)
**Windows (PowerShell):**
```powershell
go run ./cmd/secretprotector -key-file "C:\Users\Admin\Documents\master.key" -decrypt "A1B2C3D4..."
```

**Linux/Unix (Bash):**
```bash
# Ensure secure permissions first
chmod 0400 /etc/secrets/master.key

go run ./cmd/secretprotector -key-file "/etc/secrets/master.key" -decrypt "A1B2C3D4..."
```

## Library Integration
To integrate SecretProtector into your own Go application, please refer to the [SAMPLEAPP.md](./SAMPLEAPP.md) guide. It details the "Bootstrap Sequence" required to resolve keys and decrypt secrets at runtime securely.

## Architecture
For details on design choices, cryptographic standards, and project structure, see [ARCHITECTURE.md](./ARCHITECTURE.md).
