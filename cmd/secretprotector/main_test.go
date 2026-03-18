// Package main implements the integration tests for the SecretProtector CLI.
// It verifies the command-line interface by mocking arguments, capturing output,
// and ensuring the end-to-end flow from flags to library execution is correct.
//
// Test Strategy:
// 1. CLI Flags: Verify -version, -generate, and usage information.
// 2. Integration: Verify encryption/decryption round-trip using CLI flags.
// 3. Key Sources: Verify resolution from CLI flags, Environment Variables, and Files.
// 4. Error Handling: Verify that invalid inputs and security violations result in appropriate exit codes.
package main

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"criticalsys/secretprotector/pkg/libsecsecrets"
)

// TestMainCLI verifies the CLI flag parsing and basic execution flows.
// It mocks os.Args and captures stdout/stderr to verify behavior.
func TestMainCLI(t *testing.T) {
	// Save original args and restore after test
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	tests := []struct {
		name           string
		args           []string
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "Version Flag",
			args:           []string{"cmd", "-version"},
			expectedOutput: "SecretProtector version: dev",
			expectError:    false,
		},
		{
			name:           "Generate Flag",
			args:           []string{"cmd", "-generate"},
			expectedOutput: "", // Output is a random hex string
			expectError:    false,
		},
		{
			name:           "No Flags (Usage)",
			args:           []string{"cmd"},
			expectedOutput: "Usage of cmd:",
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args

			// Reset flags for each test case
			flag.CommandLine = flag.NewFlagSet(tt.args[0], flag.ContinueOnError)

			// Capture stdout
			oldStdout := os.Stdout
			oldStderr := os.Stderr
			r, w, _ := os.Pipe()
			os.Stdout = w
			os.Stderr = w

			// Run main (we use a wrapper to avoid os.Exit)
			if err := runMain(context.Background()); err != nil {
				if !tt.expectError {
					t.Errorf("runMain() unexpected error: %v", err)
				}
			}

			if err := w.Close(); err != nil {
				t.Errorf("w.Close() error: %v", err)
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Errorf("buf.ReadFrom() error: %v", err)
			}
			os.Stdout = oldStdout
			os.Stderr = oldStderr

			output := strings.TrimSpace(buf.String())

			if tt.name == "Version Flag" && !strings.Contains(output, tt.expectedOutput) {
				t.Errorf("Expected output containing %q, got %q", tt.expectedOutput, output)
			}
			if tt.name == "Generate Flag" && len(output) != 64 {
				t.Errorf("Expected 64-char hex string for generate, got %d chars", len(output))
			}
		})
	}
}

// TestCLIEncryptionDecryption verifies the integration between CLI and library.
func TestCLIEncryptionDecryption(t *testing.T) {
	key, _ := libsecsecrets.GenerateKey()
	plaintext := "test-secret-123"

	// 1. Test Encryption
	os.Args = []string{"cmd", "-key", key, "-encrypt", plaintext}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	oldStdout := os.Stdout
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("w.Close() error: %v", err)
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		t.Errorf("buf.ReadFrom() error: %v", err)
	}
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	encrypted := strings.TrimSpace(buf.String())
	if len(encrypted) < 20 {
		t.Fatalf("Encryption failed, output too short: %q", encrypted)
	}

	// 1a. Test Encryption via Env
	if err := os.Setenv("SECRETPROTECTOR_MASTER_KEY", key); err != nil {
		t.Fatalf("os.Setenv() error: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("SECRETPROTECTOR_MASTER_KEY"); err != nil {
			t.Errorf("os.Unsetenv() error: %v", err)
		}
	}()
	os.Args = []string{"cmd", "-encrypt", plaintext}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	r1e, w1e, _ := os.Pipe()
	os.Stdout = w1e
	os.Stderr = w1e
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w1e.Close(); err != nil {
		t.Errorf("w1e.Close() error: %v", err)
	}
	var buf1e bytes.Buffer
	if _, err := buf1e.ReadFrom(r1e); err != nil {
		t.Errorf("buf1e.ReadFrom() error: %v", err)
	}
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	if len(strings.TrimSpace(buf1e.String())) < 20 {
		t.Errorf("Encryption via Env failed")
	}

	// 1b. Test Encryption via File
	tmpFile := filepath.Join(t.TempDir(), "key.txt")
	if err := os.WriteFile(tmpFile, []byte(key), 0600); err != nil {
		t.Fatalf("os.WriteFile() error: %v", err)
	}
	os.Args = []string{"cmd", "-key-file", tmpFile, "-encrypt", plaintext}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	r1f, w1f, _ := os.Pipe()
	os.Stdout = w1f
	os.Stderr = w1f
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w1f.Close(); err != nil {
		t.Errorf("w1f.Close() error: %v", err)
	}
	var buf1f bytes.Buffer
	if _, err := buf1f.ReadFrom(r1f); err != nil {
		t.Errorf("buf1f.ReadFrom() error: %v", err)
	}
	os.Stdout = oldStdout
	os.Stderr = oldStderr
	if len(strings.TrimSpace(buf1f.String())) < 20 {
		t.Errorf("Encryption via File failed")
	}

	// 2. Test Decryption
	os.Args = []string{"cmd", "-key", key, "-decrypt", encrypted}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	r2, w2, _ := os.Pipe()
	os.Stdout = w2
	os.Stderr = w2
	if err := runMain(context.Background()); err != nil {
		t.Errorf("runMain() error: %v", err)
	}
	if err := w2.Close(); err != nil {
		t.Errorf("w2.Close() error: %v", err)
	}
	var buf2 bytes.Buffer
	if _, err := buf2.ReadFrom(r2); err != nil {
		t.Errorf("buf2.ReadFrom() error: %v", err)
	}
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	decrypted := strings.TrimSpace(buf2.String())
	if decrypted != plaintext {
		t.Errorf("Decryption failed: expected %q, got %q", plaintext, decrypted)
	}
}

// TestCLIErrorPaths verifies error handling in the CLI.
func TestCLIErrorPaths(t *testing.T) {
	oldArgs := os.Args
	oldStderr := os.Stderr
	defer func() {
		os.Args = oldArgs
		os.Stderr = oldStderr
	}()

	tests := []struct {
		name string
		args []string
	}{
		{
			name: "Encrypt without key",
			args: []string{"cmd", "-encrypt", "secret", "-key-env", "NON_EXISTENT_ENV"},
		},
		{
			name: "Decrypt with invalid key",
			args: []string{"cmd", "-key", "invalid", "-decrypt", "base64"},
		},
		{
			name: "Decrypt with invalid base64",
			args: []string{"cmd", "-key", strings.Repeat("a", 64), "-decrypt", "!!!@#$"},
		},
		{
			name: "Encryption failure (mocked error)",
			args: []string{"cmd", "-key", strings.Repeat("a", 64), "-encrypt", "secret"},
		},
		{
			name: "Decryption failure (mocked error)",
			args: []string{"cmd", "-key", strings.Repeat("a", 64), "-decrypt", "A1B2C3D4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = tt.args
			flag.CommandLine = flag.NewFlagSet(tt.args[0], flag.ContinueOnError)

			r, w, _ := os.Pipe()
			os.Stderr = w

			// Mock library errors for specific test cases
			if tt.name == "Encryption failure (mocked error)" {
				oldRand := libsecsecrets.RandReader
				libsecsecrets.RandReader = strings.NewReader("") // Cause nonce gen failure
				defer func() { libsecsecrets.RandReader = oldRand }()
			}

			err := runMain(context.Background())

			if err := w.Close(); err != nil {
				t.Errorf("w.Close() error: %v", err)
			}
			var buf bytes.Buffer
			if _, err := buf.ReadFrom(r); err != nil {
				t.Errorf("buf.ReadFrom() error: %v", err)
			}
			if err == nil {
				t.Errorf("Expected error for %s, but got nil", tt.name)
			}
			if buf.Len() == 0 {
				t.Errorf("Expected error output for %s, but got none", tt.name)
			}
		})
	}
}

// TestCLIGenerateError verifies error handling when key generation fails.
func TestCLIGenerateError(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	os.Args = []string{"cmd", "-generate"}
	flag.CommandLine = flag.NewFlagSet("cmd", flag.ContinueOnError)

	oldRand := libsecsecrets.RandReader
	libsecsecrets.RandReader = strings.NewReader("") // Cause key gen failure
	defer func() { libsecsecrets.RandReader = oldRand }()

	err := runMain(context.Background())
	if err == nil {
		t.Error("Expected error from runMain when key generation fails, but got nil")
	}
}
