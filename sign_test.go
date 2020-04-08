package transit

import (
	"fmt"
	"testing"
	"time"
)

func signVerifySingle(t *testing.T, kt, algo string) {
	keyName := fmt.Sprintf("k1-%d", time.Now().Unix())
	err := i.CreateKey(keyName, WithType(kt))
	if err != nil {
		t.Errorf("cannot create %s key: %s error: %s", kt, keyName, err)
		return
	}
	err = i.UpdateKeyAllowDeletion(keyName)
	if err != nil {
		t.Errorf("cannot update %s key config: %s error: %s", kt, keyName, err)
		return
	}

	input := "Something"

	signature, err := i.Sign(keyName, []byte(input), WithSignAlgo(algo))
	if err != nil {
		t.Errorf("Unable to sign with %s. error: %s", algo, err)
	}
	valid, err := i.Verify(keyName, []byte(input), signature, WithSignAlgo(algo))
	if err != nil {
		t.Errorf("Unable to verify. error: %s", err)
	}
	if !valid {
		t.Error("sign+verify: invalid result.")
	}
	valid, err = i.Verify(keyName, []byte("InvalidInput"), signature, WithSignAlgo(algo))
	if err != nil {
		t.Errorf("Unable to verify. error: %s", err)
	}
	if valid {
		t.Error("sign+verify: invalid result.")
	}

	err = i.DeleteKey(keyName)
	if err != nil {
		t.Errorf("cannot delete %s key: %s error: %s", kt, keyName, err)
	}

}

func TestSignVerify(t *testing.T) {
	algos := []string{"sha1", "sha2-224", "sha2-256", "sha2-384", "sha2-512"}
	kts := []string{"ed25519", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "rsa-2048", "rsa-4096"}
	for _, kt := range kts {
		for _, algo := range algos {
			signVerifySingle(t, kt, algo)
		}
	}
}
