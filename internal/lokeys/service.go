package lokeys

import (
	"io"
	"os"
	"time"
)

// Deps contains boundary dependencies used by command orchestration.
//
// The default command path still uses package functions, but tests can build
// a Service with custom dependencies for deterministic behavior.
type Deps struct {
	Now     func() time.Time // backup naming clock
	Stdout  io.Writer        // command user output
	Stderr  io.Writer        // key prompt output
	Mounter RamdiskMounter   // mount boundary
	Keys    KeySource        // key retrieval boundary
}

// Service groups command operations with explicit dependencies.
type Service struct {
	deps Deps
}

func (s *Service) stdout() io.Writer {
	if s == nil || s.deps.Stdout == nil {
		return os.Stdout
	}
	return s.deps.Stdout
}

func defaultDeps() Deps {
	stderr := os.Stderr
	return Deps{
		Now:     time.Now,
		Stdout:  os.Stdout,
		Stderr:  stderr,
		Mounter: defaultRamdiskMounter{},
		Keys:    defaultKeySource{stderr: stderr},
	}
}

// NewService constructs a Service with nil-safe default dependencies.
func NewService(deps Deps) *Service {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Stdout == nil {
		deps.Stdout = os.Stdout
	}
	if deps.Stderr == nil {
		deps.Stderr = os.Stderr
	}
	if deps.Mounter == nil {
		deps.Mounter = defaultRamdiskMounter{}
	}
	if deps.Keys == nil {
		deps.Keys = defaultKeySource{stderr: deps.Stderr}
	}
	return &Service{deps: deps}
}

func defaultService() *Service {
	return NewService(defaultDeps())
}
