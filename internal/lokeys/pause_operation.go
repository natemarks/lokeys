package lokeys

import "fmt"

// RunPause marks one managed file as paused in config.
func RunPause(pathArg string) error {
	return defaultService().RunPause(pathArg)
}

// RunPause marks one managed file as paused in config.
func (s *Service) RunPause(pathArg string) error {
	vlogf("pause start path=%s", pathArg)
	return s.runSetPaused(pathArg, true)
}

// RunUnpause marks one managed file as unpaused in config.
func RunUnpause(pathArg string) error {
	return defaultService().RunUnpause(pathArg)
}

// RunUnpause marks one managed file as unpaused in config.
func (s *Service) RunUnpause(pathArg string) error {
	vlogf("unpause start path=%s", pathArg)
	return s.runSetPaused(pathArg, false)
}

func (s *Service) runSetPaused(pathArg string, paused bool) error {
	fullPath, err := expandUserPath(pathArg)
	if err != nil {
		return err
	}
	portable, err := portablePath(fullPath)
	if err != nil {
		return err
	}

	cfg, _, err := s.ensureConfig()
	if err != nil {
		return fmt.Errorf("ensure config: %w", err)
	}

	idx := cfg.protectedFileIndex(portable)
	if idx == -1 {
		fmt.Fprintf(s.stdout(), "%s is not protected.\n", portable)
		return nil
	}

	if cfg.ProtectedFiles[idx].Paused == paused {
		if paused {
			fmt.Fprintf(s.stdout(), "%s already paused.\n", portable)
		} else {
			fmt.Fprintf(s.stdout(), "%s already unpaused.\n", portable)
		}
		return nil
	}

	updated := &config{ProtectedFiles: cfg.protectedFileEntries()}
	updated.setProtectedFilePaused(portable, paused)
	updated.KMSBypassFiles = append([]string{}, cfg.KMSBypassFiles...)
	if cfg.KMS != nil {
		kms := *cfg.KMS
		updated.KMS = &kms
	}

	if err := s.writeConfig(updated); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	if paused {
		fmt.Fprintf(s.stdout(), "paused %s\n", portable)
		vlogf("pause complete path=%s", portable)
		return nil
	}
	fmt.Fprintf(s.stdout(), "unpaused %s\n", portable)
	vlogf("unpause complete path=%s", portable)
	return nil
}
