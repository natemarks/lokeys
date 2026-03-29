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

func protectedPaths(entries []protectedFile) []string {
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		paths = append(paths, entry.Path)
	}
	return paths
}

func containsProtectedPath(entries []protectedFile, path string) bool {
	for _, entry := range entries {
		if entry.Path == path {
			return true
		}
	}
	return false
}
