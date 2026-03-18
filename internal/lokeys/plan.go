package lokeys

import "os"

type actionKind string

const (
	actionEnsureEncryptedDir actionKind = "ensure_encrypted_dir"
	actionEnsureParentDir    actionKind = "ensure_parent_dir"
	actionCopyFile           actionKind = "copy_file"
	actionEncryptFile        actionKind = "encrypt_file"
	actionDecryptFile        actionKind = "decrypt_file"
	actionReplaceWithSymlink actionKind = "replace_with_symlink"
	actionRestoreManagedLink actionKind = "restore_managed_symlink"
	actionRemovePath         actionKind = "remove_path"
	actionWriteConfig        actionKind = "write_config"
)

type action struct {
	Kind actionKind

	Path   string
	Source string
	Target string

	Perm   os.FileMode
	Key    []byte
	UseKMS bool
	KMS    kmsRuntimeConfig

	Config         *config
	IgnoreNotExist bool

	HomePath     string
	InsecurePath string
	SecurePath   string
}

type plan struct {
	Actions []action
}
