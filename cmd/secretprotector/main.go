// Package main implements the CLI utility for the SecretProtector system.
// It provides an administrative interface for generating master keys,
// as well as encrypting and decrypting secrets using the libsecsecrets library.
//
// Objective:
// To provide a standalone tool for DevOps and SecOps to manage the lifecycle
// of encrypted credentials without exposing plaintext values.
//
// Functionality:
// - Generate new 32-byte master keys (CSPRNG).
// - Encrypt plaintext strings using AES-256-GCM.
// - Decrypt Base64-encoded ciphertexts back to plaintext.
// - Support for multiple key sources (Flag, Environment, File) with strict security boundaries.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"criticalsys/secretprotector/pkg/libsecsecrets"
)

// version is the application version, which can be overridden at compile time
// using -ldflags="-X main.version=..."
var version = "dev"

func main() {
	ctx := context.Background()
	if err := runMain(ctx); err != nil {
		os.Exit(1)
	}
}

// runMain is the primary entry point for the CLI logic.
// It handles flag parsing, key resolution, and dispatches to library functions.
//
// Data Flow:
//  1. Parse CLI flags and validate mutual exclusivity (implicit by priority).
//  2. If 'generate', call libsecsecrets.GenerateKey and exit.
//  3. Resolve the master key using libsecsecrets.ResolveKey.
//  4. Perform encryption or decryption based on provided flags.
//     Supports any sensitive application secret (e.g., SFTP, API, DB).
//  5. Securely zero out the resolved master key buffer before exiting.
func runMain(ctx context.Context) error {
	// CLI Flag Definitions
	versionFlag := flag.Bool("version", false, "Print the version information and exit")
	generateFlag := flag.Bool("generate", false, "Generate a new 32-byte Master Key (64-char hex string)")
	encryptFlag := flag.String("encrypt", "", "Plaintext string to obfuscate")
	decryptFlag := flag.String("decrypt", "", "Base64-encoded ciphertext to decrypt")

	// Key Source Configuration Flags
	keyFlag := flag.String("key", "", "Provide the Master Key directly as a 64-character hex string")
	keyEnvFlag := flag.String("key-env", libsecsecrets.DefaultKeyEnv, "The name of the environment variable containing the Master Key")
	keyFileFlag := flag.String("key-file", "", "The fully qualified path to a file containing the Master Key")

	flag.Parse()

	// Execution Flow: Version Check
	if *versionFlag {
		fmt.Printf("SecretProtector version: %s\n", version)
		return nil
	}

	// Execution Flow: Key Generation
	// This branch does not require an existing key.
	if *generateFlag {
		key, err := libsecsecrets.GenerateKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
			return err
		}
		defer func() {
			// Note: The key is a string (hex encoded), so zeroing is limited.
			// In a production app, we'd use []byte for keys as much as possible.
		}()
		fmt.Println(key)
		return nil
	}

	// Execution Flow: Encryption
	// Requires a master key resolved from flags, env, or file.
	if *encryptFlag != "" {
		key, err := libsecsecrets.ResolveKey(ctx, *keyFlag, *keyEnvFlag, *keyFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving key: %v\n", err)
			return err
		}
		defer libsecsecrets.ZeroBuffer(key)

		encrypted, err := libsecsecrets.Encrypt(ctx, *encryptFlag, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting: %v\n", err)
			return err
		}
		fmt.Println(encrypted)
		return nil
	}

	// Execution Flow: Decryption
	// Requires a master key resolved from flags, env, or file.
	if *decryptFlag != "" {
		key, err := libsecsecrets.ResolveKey(ctx, *keyFlag, *keyEnvFlag, *keyFileFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving key: %v\n", err)
			return err
		}
		defer libsecsecrets.ZeroBuffer(key)

		decrypted, err := libsecsecrets.Decrypt(ctx, *decryptFlag, key)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting: %v\n", err)
			return err
		}
		defer func() {
			// Zero out the decrypted plaintext if it was a slice,
			// but here it's returned as a string.
		}()
		fmt.Println(decrypted)
		return nil
	}

	// Default: Show usage if no valid flags are provided.
	flag.Usage()
	return nil
}
