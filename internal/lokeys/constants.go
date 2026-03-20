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
	HomeDirEnv          = "LOKEYS_HOME"
	ConfigPathEnv       = "LOKEYS_CONFIG_PATH"
	SecureDirEnv        = "LOKEYS_SECURE_DIR"
	InsecureDirEnv      = "LOKEYS_INSECURE_DIR"
	fileMagicV1         = "LOKEYS1"
	fileMagicV2         = "LOKEYS2"
	fileMagicV3         = "LOKEYS3"
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
	ProtectedFiles []string   `json:"protectedFiles"`
	KMS            *kmsConfig `json:"kms,omitempty"`
	KMSBypassFiles []string   `json:"kmsBypassFiles,omitempty"`
}

type kmsConfig struct {
	Enabled           bool              `json:"enabled"`
	KeyID             string            `json:"keyId,omitempty"`
	Region            string            `json:"region,omitempty"`
	Profile           string            `json:"profile,omitempty"`
	Alias             string            `json:"alias,omitempty"`
	EncryptionContext map[string]string `json:"encryptionContext,omitempty"`
}
