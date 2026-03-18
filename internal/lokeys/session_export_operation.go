package lokeys

import "fmt"

// RunSessionExport prompts for a key and returns an export command line.
func RunSessionExport() (string, error) {
	return defaultService().RunSessionExport()
}

// RunSessionExport prompts for a key and returns an export command line.
func (s *Service) RunSessionExport() (string, error) {
	_, encoded, err := s.deps.Keys.PromptForKey()
	if err != nil {
		return "", fmt.Errorf("prompt for key: %w", err)
	}
	return fmt.Sprintf("export %s='%s'", SessionKeyEnv, encoded), nil
}
