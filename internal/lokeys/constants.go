package lokeys

import "os"

// SessionKeyEnv stores the encoded key used by lokeys commands.
const (
	configFileRel       = ".config/lokeys"
	defaultDecryptedRel = ".lokeys/insecure"
	defaultEncryptedRel = ".lokeys/secure"
	defaultRamdiskSize  = "100m"
	defaultMountMode    = "0700"
	SessionKeyEnv       = "LOKEYS_SESSION_KEY"
	fileMagicV1         = "LOKEYS1"
	fileMagicV2         = "LOKEYS2"
	configFilePerm      = os.FileMode(0600)
	dirPerm             = os.FileMode(0700)
)

const (
	kdfScryptID       = 1
	kdfSaltSize       = 16
	kdfDerivedKeySize = 32
	kdfScryptN        = 1 << 15
	kdfScryptR        = 8
	kdfScryptP        = 1
)

type config struct {
	ProtectedFiles []string `json:"protectedFiles"`
}
