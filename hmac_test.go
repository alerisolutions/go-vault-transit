package transit

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func TestHmac(t *testing.T) {

	inp := []byte("Something")

	keyName := fmt.Sprintf("k1-%d", time.Now().Unix())
	keyType := "aes256-gcm96"
	err := i.CreateKey(keyName, WithType(keyType), WithConvergentEncryption(), WithDerived(), WithExportable(), WithPlaintextBackup())
	if err != nil {
		t.Errorf("cannot create %s key: %s error: %s", keyType, keyName, err)
		return
	}
	err = i.UpdateKeyAllowDeletion(keyName)
	if err != nil {
		t.Errorf("cannot update %s key config: %s error: %s", keyType, keyName, err)
		return
	}

	hmac1, err := i.Hmac(keyName, inp, WithHmacAlgo("sha2-512"))
	if err != nil {
		t.Errorf("Unable to hmac value. error: %s", err)
	}

	hmac1r, err := i.HmacFromReader(keyName, bytes.NewReader(inp), WithHmacAlgo("sha2-512"))
	if err != nil {
		t.Errorf("Unable to hmac stream. error: %s", err)
	}
	if hmac1 != hmac1r {
		t.Errorf("error comparing values (stream/bytes)")
	}

	bOk, err := i.VerifyHmac(keyName, inp, hmac1, WithHmacAlgo("sha2-512"))
	if err != nil {
		t.Errorf("Unable to hmac value. error: %s", err)
	}
	if !bOk {
		t.Error("hmac verify returned invalid result.")
	}

	bOk, err = i.VerifyHmacFromReader(keyName, bytes.NewReader(inp), hmac1, WithHmacAlgo("sha2-512"))
	if err != nil {
		t.Errorf("Unable to hmac stream. error: %s", err)
	}
	if !bOk {
		t.Error("hmac verify returned invalid result.")
	}

	bOk, err = i.VerifyHmac(keyName, inp, hmac1, WithHmacAlgo("sha2-256"))
	if err != nil {
		t.Errorf("Unable to hmac value. error: %s", err)
	}
	if bOk {
		t.Error("hmac verify returned invalid result.")
	}
	err = i.DeleteKey(keyName)
	if err != nil {
		t.Errorf("cannot delete %s key: %s error: %s", keyType, keyName, err)
	}

}
