# Sample Application Integration Guide

This document explains how to integrate the `libsecsecrets` library into your Go application (e.g., an SFTP client, API consumer, or database connector) for secure, runtime decryption of secrets.

## 1. Project Structure

Your application should follow a clean separation of concerns:

```text
/my-sftp-project
├── go.mod
├── config.json
└── main.go
```

## 2. Configuration (`config.json`)

Store the obfuscated password and the path to the master key in your configuration file.

```json
{
  "host": "sftp.example.com",
  "user": "deploy_user",
  "encrypted_pass": "A1B2C3D4...",
  "master_key_path": "/etc/secrets/key.txt"
}
```

## 3. Bootstrap Sequence (`main.go`)

Follow these steps to safely initialize your application.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"criticalsys/secretprotector/pkg/libsecsecrets"
)

type Config struct {
	Host          string `json:"host"`
	User          string `json:"user"`
	EncryptedPass string `json:"encrypted_pass"`
	MasterKeyPath string `json:"master_key_path"`
}

func main() {
	ctx := context.Background()

	// 1. Load Configuration
	cfg, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 2. Resolve Master Key
	// Priority: Flag (if any) > Environment Variable > File Path from config
	masterKey, err := libsecsecrets.ResolveKey(ctx, "", "SECRETPROTECTOR_MASTER_KEY", cfg.MasterKeyPath)
	if err != nil {
		log.Fatalf("Security failure: %v", err)
	}
	defer libsecsecrets.ZeroBuffer(masterKey)

	// 3. Decrypt Secret at Runtime
	realPass, err := libsecsecrets.Decrypt(ctx, cfg.EncryptedPass, masterKey)
	if err != nil {
		log.Fatalf("Decryption failure: %v", err)
	}
	defer func() {
		// realPass is a string, so we cannot ZeroBuffer it directly.
		// In high-security apps, consider using []byte for secrets.
	}()

	// 4. Use Secret (Memory Only)
	fmt.Printf("Connecting to %s as %s...\n", cfg.Host, cfg.User)
	performSecureOperation(cfg.Host, cfg.User, realPass)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func performSecureOperation(host, user, pass string) {
	// Mock operation logic (e.g., SFTP, API, DB)
	// The 'pass' variable is never written to logs or disk
	fmt.Println("Secure operation established successfully.")
}
```

## 4. Security Best Practices

*   **Memory Hygiene:** Never print the decrypted `realPass` to `stdout` or logs. Always use `defer libsecsecrets.ZeroBuffer(masterKey)` to clear sensitive keys from memory as soon as they are no longer needed.
*   **Context Support:** Use `context.Context` for all library calls to support timeouts and cancellations in production environments.
*   **Fail Fast:** If the master key cannot be resolved or decryption fails, the application **must** terminate immediately.
*   **Key Protection:** On Linux, ensure the key file has `0400` permissions. On Windows, store the key in a restricted user directory.
