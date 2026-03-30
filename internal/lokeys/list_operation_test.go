package lokeys

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This module validates list-specific behavior beyond core tracked-file status
// reporting, including discovery of externally created insecure files.

// TestRunList_ShowsExternallyCreatedInsecureFileAsUntracked verifies list
// surfaces untracked files that were created directly under the RAM-disk tree.
//
// How it works:
// 1. Create an empty config under a temp HOME.
// 2. Write a regular file directly in ~/.lokeys/insecure outside tracked config.
// 3. Run list with captured stdout and assert UNTRACKED_INSECURE output.
func TestRunList_ShowsExternallyCreatedInsecureFileAsUntracked(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}
	insecurePath := filepath.Join(home, defaultDecryptedRel, "external", "new.txt")
	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("external\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}

	stdout := &bytes.Buffer{}
	svc := NewService(Deps{Stdout: stdout, Stderr: &bytes.Buffer{}, Mounter: testMounter{}, Keys: testKeySource{}})
	if err := svc.RunList(); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "$HOME/external/new.txt") {
		t.Fatalf("expected derived portable path in output, got: %q", out)
	}
	if !strings.Contains(out, "UNTRACKED_INSECURE") {
		t.Fatalf("expected untracked insecure status in output, got: %q", out)
	}
}

func TestRunList_ShowsPausedMarkerForPausedManagedFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key, encoded := mustEncodedSessionKey(t)
	t.Setenv(SessionKeyEnv, encoded)

	if _, _, err := ensureConfig(); err != nil {
		t.Fatalf("ensure config: %v", err)
	}

	portable := "$HOME/docs/paused.txt"
	insecurePath := filepath.Join(home, defaultDecryptedRel, "docs", "paused.txt")
	securePath := filepath.Join(home, defaultEncryptedRel, "docs", "paused.txt")

	if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
		t.Fatalf("mkdir insecure parent: %v", err)
	}
	if err := os.WriteFile(insecurePath, []byte("paused-data\n"), 0600); err != nil {
		t.Fatalf("write insecure file: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(securePath), dirPerm); err != nil {
		t.Fatalf("mkdir secure parent: %v", err)
	}
	ciphertext, err := encryptBytes([]byte("paused-data\n"), key)
	if err != nil {
		t.Fatalf("encrypt secure file: %v", err)
	}
	if err := os.WriteFile(securePath, ciphertext, 0600); err != nil {
		t.Fatalf("write secure file: %v", err)
	}

	if err := writeConfig(newConfigFixtureBuilder().WithManagedFilePaused(portable, true).Build()); err != nil {
		t.Fatalf("write config: %v", err)
	}

	stdout := &bytes.Buffer{}
	svc := NewService(Deps{Stdout: stdout, Stderr: &bytes.Buffer{}, Mounter: testMounter{}, Keys: testKeySource{}})
	if err := svc.RunList(); err != nil {
		t.Fatalf("RunList: %v", err)
	}
	out := stdout.String()
	if !strings.Contains(out, portable) {
		t.Fatalf("expected managed portable path in output, got: %q", out)
	}
	if !strings.Contains(out, "OK  PAUSED") {
		t.Fatalf("expected paused marker in output, got: %q", out)
	}
}

func TestRunList_StatusMatrix(t *testing.T) {
	type testCase struct {
		name          string
		insecureExist bool
		secureExist   bool
		hashesMatch   bool
		paused        bool
		wantStatus    string
	}

	computeExpectedStatus := func(insecureExist bool, secureExist bool, hashesMatch bool) string {
		switch {
		case !insecureExist:
			return "MISSING_INSECURE"
		case !secureExist:
			return "MISSING_SECURE"
		case !hashesMatch:
			return "MISMATCH"
		default:
			return "OK"
		}
	}

	cases := []testCase{}
	for _, insecureExist := range []bool{false, true} {
		for _, secureExist := range []bool{false, true} {
			for _, hashesMatch := range []bool{false, true} {
				for _, paused := range []bool{false, true} {
					cases = append(cases, testCase{
						name:          fmt.Sprintf("insecure_%t_secure_%t_match_%t_paused_%t", insecureExist, secureExist, hashesMatch, paused),
						insecureExist: insecureExist,
						secureExist:   secureExist,
						hashesMatch:   hashesMatch,
						paused:        paused,
						wantStatus:    computeExpectedStatus(insecureExist, secureExist, hashesMatch),
					})
				}
			}
		}
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			key, encoded := mustEncodedSessionKey(t)
			t.Setenv(SessionKeyEnv, encoded)

			if _, _, err := ensureConfig(); err != nil {
				t.Fatalf("ensure config: %v", err)
			}

			portable := "$HOME/docs/matrix.txt"
			if err := writeConfig(newConfigFixtureBuilder().WithManagedFilePaused(portable, tc.paused).Build()); err != nil {
				t.Fatalf("write config: %v", err)
			}

			insecurePath := filepath.Join(home, defaultDecryptedRel, "docs", "matrix.txt")
			securePath := filepath.Join(home, defaultEncryptedRel, "docs", "matrix.txt")

			insecurePlain := []byte("matrix-insecure\n")
			securePlain := []byte("matrix-insecure\n")
			if !tc.hashesMatch {
				securePlain = []byte("matrix-secure-different\n")
			}

			if tc.insecureExist {
				if err := os.MkdirAll(filepath.Dir(insecurePath), dirPerm); err != nil {
					t.Fatalf("mkdir insecure parent: %v", err)
				}
				if err := os.WriteFile(insecurePath, insecurePlain, 0600); err != nil {
					t.Fatalf("write insecure file: %v", err)
				}
			}

			if tc.secureExist {
				if err := os.MkdirAll(filepath.Dir(securePath), dirPerm); err != nil {
					t.Fatalf("mkdir secure parent: %v", err)
				}
				ciphertext, err := encryptBytes(securePlain, key)
				if err != nil {
					t.Fatalf("encrypt secure file: %v", err)
				}
				if err := os.WriteFile(securePath, ciphertext, 0600); err != nil {
					t.Fatalf("write secure file: %v", err)
				}
			}

			stdout := &bytes.Buffer{}
			svc := NewService(Deps{Stdout: stdout, Stderr: &bytes.Buffer{}, Mounter: testMounter{}, Keys: testKeySource{}})
			if err := svc.RunList(); err != nil {
				t.Fatalf("RunList: %v", err)
			}

			line, found := findListLine(stdout.String(), portable)
			if !found {
				t.Fatalf("expected output line for %s, got: %q", portable, stdout.String())
			}

			if !strings.Contains(line, "  "+tc.wantStatus) {
				t.Fatalf("expected status %q in line %q", tc.wantStatus, line)
			}

			hasPaused := strings.Contains(line, "  PAUSED")
			if hasPaused != tc.paused {
				t.Fatalf("paused marker mismatch: want=%t line=%q", tc.paused, line)
			}
		})
	}
}

func findListLine(output string, portable string) (string, bool) {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, portable+"  insecure=") {
			return line, true
		}
	}
	return "", false
}
