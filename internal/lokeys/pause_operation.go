package lokeys

import "fmt"

// RunPause marks one managed file as paused in config.
func RunPause(pathArg string) error {
	return defaultService().RunPause(pathArg)
}

// RunPause marks one managed file as paused in config.
func (s *Service) RunPause(pathArg string) error {
	_ = s
	_ = pathArg
	return fmt.Errorf("pause command is not implemented yet")
}

// RunUnpause marks one managed file as unpaused in config.
func RunUnpause(pathArg string) error {
	return defaultService().RunUnpause(pathArg)
}

// RunUnpause marks one managed file as unpaused in config.
func (s *Service) RunUnpause(pathArg string) error {
	_ = s
	_ = pathArg
	return fmt.Errorf("unpause command is not implemented yet")
}
