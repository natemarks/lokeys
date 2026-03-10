package lokeys

import "os"

// SessionKeyEnv stores the encoded session key for --session mode.
const (
	configFileRel       = ".config/lokeys"
	defaultDecryptedRel = ".lokeys/insecure"
	defaultEncryptedRel = ".lokeys/secure"
	defaultRamdiskSize  = "100m"
	defaultMountMode    = "0700"
	SessionKeyEnv       = "LOKEYS_SESSION_KEY"
	fileMagic           = "LOKEYS1"
	configFilePerm      = os.FileMode(0600)
	dirPerm             = os.FileMode(0700)
)

type config struct {
	ProtectedFiles []string `json:"protectedFiles"`
}
