package lokeys

import (
	"path/filepath"
	"testing"
)

func TestDecideSealKMSPolicy(t *testing.T) {
	cfg := newConfigFixtureBuilder().WithKMSEnabled("alias/lokeys", "us-east-1").Build()

	t.Run("requires kms for tracked files using kms", func(t *testing.T) {
		decision := decideSealKMSPolicy(cfg, []trackedFile{{Portable: "$HOME/docs/secret.txt"}}, nil, map[string]struct{}{})
		if !decision.RequiresKMS {
			t.Fatalf("expected RequiresKMS=true")
		}
		if len(decision.BlockedBypass) != 0 {
			t.Fatalf("expected no blocked bypass paths, got %#v", decision.BlockedBypass)
		}
	})

	t.Run("blocks discovered aws credential paths without explicit bypass", func(t *testing.T) {
		discovered := []trackedFile{{Portable: "$HOME/.aws/sso/cache/token.json"}}
		decision := decideSealKMSPolicy(cfg, nil, discovered, map[string]struct{}{})
		if decision.RequiresKMS {
			t.Fatalf("expected RequiresKMS=false for aws credential discovered files")
		}
		if len(decision.BlockedBypass) != 1 || decision.BlockedBypass[0] != "$HOME/.aws/sso/cache/token.json" {
			t.Fatalf("unexpected blocked bypass paths: %#v", decision.BlockedBypass)
		}
	})

	t.Run("allows discovered aws credential paths with explicit bypass", func(t *testing.T) {
		discovered := []trackedFile{{Portable: "$HOME/.aws/sso/cache/token.json"}}
		allow := map[string]struct{}{"$HOME/.aws/sso/cache/token.json": {}}
		decision := decideSealKMSPolicy(cfg, nil, discovered, allow)
		if decision.RequiresKMS {
			t.Fatalf("expected RequiresKMS=false for bypassed aws credential file")
		}
		if len(decision.BlockedBypass) != 0 {
			t.Fatalf("expected no blocked bypass paths, got %#v", decision.BlockedBypass)
		}
	})

	t.Run("auto bypass aws config does not block", func(t *testing.T) {
		discovered := []trackedFile{{Portable: filepath.Join("$HOME", ".aws", "config")}}
		decision := decideSealKMSPolicy(cfg, nil, discovered, map[string]struct{}{})
		if decision.RequiresKMS {
			t.Fatalf("expected RequiresKMS=false for auto-bypass file")
		}
		if len(decision.BlockedBypass) != 0 {
			t.Fatalf("expected no blocked bypass paths, got %#v", decision.BlockedBypass)
		}
	})
}

func TestPlanUnsealExecution(t *testing.T) {
	cfg := newConfigFixtureBuilder().
		WithKMSEnabled("alias/lokeys", "us-east-1").
		WithKMSBypassFiles("$HOME/docs/local.txt").
		Build()

	tracked := []trackedFile{
		{Portable: "$HOME/docs/local.txt", HomePath: "/home/u/docs/local.txt", InsecurePath: "/ram/docs/local.txt", SecurePath: "/secure/docs/local.txt"},
		{Portable: "$HOME/docs/kms.txt", HomePath: "/home/u/docs/kms.txt", InsecurePath: "/ram/docs/kms.txt", SecurePath: "/secure/docs/kms.txt"},
		{Portable: filepath.Join("$HOME", ".aws", "config"), HomePath: "/home/u/.aws/config", InsecurePath: "/ram/.aws/config", SecurePath: "/secure/.aws/config"},
	}

	execPlan := planUnsealExecution(cfg, tracked, []byte("test-key"))
	if len(execPlan.AllTracked) != 3 {
		t.Fatalf("expected 3 tracked files, got %d", len(execPlan.AllTracked))
	}
	if len(execPlan.LocalTracked) != 2 {
		t.Fatalf("expected 2 local tracked files, got %d", len(execPlan.LocalTracked))
	}
	if len(execPlan.KMSTracked) != 1 {
		t.Fatalf("expected 1 kms tracked file, got %d", len(execPlan.KMSTracked))
	}
	if !execPlan.AWSSeededLocal {
		t.Fatalf("expected AWSSeededLocal=true when local tracked includes aws auto-bypass path")
	}

	if got := len(execPlan.LocalPlan.Actions); got != 6 {
		t.Fatalf("expected 6 local plan actions, got %d", got)
	}
	if got := len(execPlan.KMSPlan.Actions); got != 3 {
		t.Fatalf("expected 3 kms plan actions, got %d", got)
	}
}

func TestPlanTrackedListStatus(t *testing.T) {
	cases := []struct {
		name     string
		observed listTrackedObservation
		want     listStatus
	}{
		{
			name: "missing insecure dominates",
			observed: listTrackedObservation{
				InsecureFound: false,
				SecureFound:   true,
				InsecureHash:  "",
				SecureHash:    "abc",
			},
			want: statusMissingInsecure,
		},
		{
			name: "missing secure when insecure exists",
			observed: listTrackedObservation{
				InsecureFound: true,
				SecureFound:   false,
				InsecureHash:  "abc",
				SecureHash:    "",
			},
			want: statusMissingSecure,
		},
		{
			name: "mismatch when both exist but hashes differ",
			observed: listTrackedObservation{
				InsecureFound: true,
				SecureFound:   true,
				InsecureHash:  "abc",
				SecureHash:    "def",
			},
			want: statusMismatch,
		},
		{
			name: "ok when both exist and hashes match",
			observed: listTrackedObservation{
				InsecureFound: true,
				SecureFound:   true,
				InsecureHash:  "abc",
				SecureHash:    "abc",
			},
			want: statusOK,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := planTrackedListStatus(tc.observed)
			if got != tc.want {
				t.Fatalf("status mismatch: got %s want %s", got, tc.want)
			}
		})
	}
}
