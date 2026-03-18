package lokeys

import "fmt"

func (s *Service) applyPlan(p plan) error {
	vlogf("apply plan with %d actions", len(p.Actions))
	for _, a := range p.Actions {
		if err := s.applyAction(a); err != nil {
			return err
		}
	}
	vlogf("apply plan complete")
	return nil
}

func (s *Service) applyAction(a action) error {
	vlogf("action=%s path=%s source=%s", a.Kind, a.Path, a.Source)
	switch a.Kind {
	case actionEnsureEncryptedDir:
		if err := ensureEncryptedDir(a.Path); err != nil {
			return fmt.Errorf("ensure encrypted dir %s: %w", a.Path, err)
		}
		return nil
	case actionEnsureParentDir:
		if err := ensureParentDir(a.Path); err != nil {
			return fmt.Errorf("ensure parent dir %s: %w", a.Path, err)
		}
		return nil
	case actionCopyFile:
		if err := copyFile(a.Source, a.Path, a.Perm); err != nil {
			return fmt.Errorf("copy file %s to %s: %w", a.Source, a.Path, err)
		}
		return nil
	case actionEncryptFile:
		if err := encryptFile(a.Source, a.Path, a.Key, a.UseKMS, a.KMS); err != nil {
			return fmt.Errorf("encrypt file %s to %s: %w", a.Source, a.Path, err)
		}
		return nil
	case actionDecryptFile:
		if err := decryptFile(a.Source, a.Path, a.Key, a.UseKMS, a.KMS); err != nil {
			return fmt.Errorf("decrypt file %s to %s: %w", a.Source, a.Path, err)
		}
		return nil
	case actionReplaceWithSymlink:
		if err := replaceWithSymlink(a.Path, a.Target); err != nil {
			return fmt.Errorf("replace with symlink %s -> %s: %w", a.Path, a.Target, err)
		}
		return nil
	case actionRestoreManagedLink:
		if err := s.restoreIfManagedSymlink(a.HomePath, a.InsecurePath, a.SecurePath); err != nil {
			return fmt.Errorf("restore managed symlink %s: %w", a.HomePath, err)
		}
		return nil
	case actionRemovePath:
		err := removePath(a.Path, a.IgnoreNotExist)
		if err != nil {
			return fmt.Errorf("remove path %s: %w", a.Path, err)
		}
		return nil
	case actionWriteConfig:
		if err := writeConfig(a.Config); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported action kind: %s", a.Kind)
	}
}
