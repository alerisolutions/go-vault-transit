package transit

import (
	"testing"
)

func TestHash(t *testing.T) {
	hash1, err := i.Hash([]byte("Something"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	hash2, err := i.Hash([]byte("Something"), WithHashAlgo("sha2-256"), WithHashFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash1 != hash2 {
		t.Error("Error comparing values")
	}

	hash3, err := i.Hash([]byte("Something"), WithHashAlgo("sha2-224"), WithHashFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash3 == hash2 {
		t.Error("Error comparing values")
	}

	hash4, err := i.Hash([]byte("Something"), WithHashAlgo("sha2-224"), WithHashFormat("base64"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash3 == hash4 {
		t.Error("Error comparing values")
	}

	_, err = i.Hash([]byte("Something"), WithHashAlgo("md5"), WithHashFormat("base64"))
	if err == nil {
		t.Error("invalid algo was accepted. error")
	}
}
