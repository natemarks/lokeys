package lokeys

func cloneProtectedFiles(entries []protectedFile) []protectedFile {
	if len(entries) == 0 {
		return []protectedFile{}
	}
	cloned := make([]protectedFile, 0, len(entries))
	for _, entry := range entries {
		cloned = append(cloned, entry)
	}
	return cloned
}

func (c *config) protectedFileIndex(path string) int {
	if c == nil {
		return -1
	}
	for i, entry := range c.ProtectedFiles {
		if entry.Path == path {
			return i
		}
	}
	return -1
}

func (c *config) hasProtectedFile(path string) bool {
	return c.protectedFileIndex(path) >= 0
}

func (c *config) setProtectedFilePaused(path string, paused bool) bool {
	idx := c.protectedFileIndex(path)
	if idx < 0 {
		return false
	}
	c.ProtectedFiles[idx].Paused = paused
	return true
}

func (c *config) removeProtectedFile(path string) bool {
	idx := c.protectedFileIndex(path)
	if idx < 0 {
		return false
	}
	c.ProtectedFiles = append(c.ProtectedFiles[:idx], c.ProtectedFiles[idx+1:]...)
	return true
}

func (c *config) protectedFilePaths() []string {
	if c == nil {
		return []string{}
	}
	return protectedPaths(c.ProtectedFiles)
}

func (c *config) protectedFileEntries() []protectedFile {
	if c == nil {
		return []protectedFile{}
	}
	return cloneProtectedFiles(c.ProtectedFiles)
}

func protectedPaths(entries []protectedFile) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	return paths
}
