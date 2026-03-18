package lokeys

import (
	"fmt"
	"path/filepath"
)

// trackedFile captures canonical paths for a protected file across home, RAM, and secure storage.
type trackedFile struct {
	Portable     string
	Rel          string
	HomePath     string
	InsecurePath string
	SecurePath   string
}

func buildTrackedFileFromPortable(home string, secureDir string, insecureDir string, portable string) (trackedFile, error) {
	homePath, err := expandPortablePath(portable)
	if err != nil {
		return trackedFile{}, err
	}
	rel, err := relToBase(home, homePath)
	if err != nil {
		return trackedFile{}, fmt.Errorf("path must be under $HOME")
	}
	return trackedFile{
		Portable:     portable,
		Rel:          rel,
		HomePath:     homePath,
		InsecurePath: filepath.Join(insecureDir, rel),
		SecurePath:   filepath.Join(secureDir, rel),
	}, nil
}

func buildTrackedFileFromHomePath(home string, secureDir string, insecureDir string, homePath string) (trackedFile, error) {
	rel, err := relToBase(home, homePath)
	if err != nil {
		return trackedFile{}, fmt.Errorf("path must be under $HOME")
	}
	portable, err := portablePath(homePath)
	if err != nil {
		return trackedFile{}, err
	}
	return trackedFile{
		Portable:     portable,
		Rel:          rel,
		HomePath:     homePath,
		InsecurePath: filepath.Join(insecureDir, rel),
		SecurePath:   filepath.Join(secureDir, rel),
	}, nil
}

func buildTrackedFileFromInsecurePath(home string, secureDir string, insecureDir string, fullPath string) (trackedFile, bool, error) {
	rel, fromInsecure, err := relToInsecureRoot(fullPath, insecureDir)
	if err != nil {
		return trackedFile{}, false, err
	}
	if !fromInsecure {
		return trackedFile{}, false, nil
	}
	homePath := homePathFromInsecureRel(home, rel)
	portable, err := portablePath(homePath)
	if err != nil {
		return trackedFile{}, false, err
	}
	return trackedFile{
		Portable:     portable,
		Rel:          rel,
		HomePath:     homePath,
		InsecurePath: fullPath,
		SecurePath:   filepath.Join(secureDir, rel),
	}, true, nil
}
