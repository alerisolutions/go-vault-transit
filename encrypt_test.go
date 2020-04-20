package transit

import (
	"fmt"
	"testing"
	"time"
)

func encryptDecryptSingle(t *testing.T, keyType string) {
	keyName := fmt.Sprintf("k1-%d", time.Now().Unix())
	err := i.CreateKey(keyName, WithType(keyType))
	if err != nil {
		t.Errorf("cannot create %s key: %s error: %s", keyType, keyName, err)
		return
	}
	err = i.UpdateKeyAllowDeletion(keyName)
	if err != nil {
		t.Errorf("cannot update %s key config: %s error: %s", keyType, keyName, err)
		return
	}

	plaintext := "Something"

	ciphertext, err := i.Encrypt(keyName, []byte(plaintext))
	if err != nil {
		t.Errorf("Unable to encrypt. error: %s", err)
	}
	decrypted, err := i.Decrypt(keyName, ciphertext)
	if err != nil {
		t.Errorf("Unable to decrypt. error: %s", err)
	}
	if plaintext != string(decrypted) {
		t.Error("encrypt+decrypt: invalid result.")
	}

	err = i.DeleteKey(keyName)
	if err != nil {
		t.Errorf("cannot delete %s key: %s error: %s", keyType, keyName, err)
	}

}

func TestEncryptDecrypt(t *testing.T) {
	kts := []string{"aes128-gcm96", "aes256-gcm96", "chacha20-poly1305", "rsa-2048", "rsa-4096"}
	for _, kt := range kts {
		encryptDecryptSingle(t, kt)
	}
}
