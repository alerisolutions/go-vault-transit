package transit

import (
	"testing"
)

/*
var (
	i *Transit
)
*/

func TestHash(t *testing.T) {
	hash1, err := i.Hash([]byte("Something"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	hash2, err := i.Hash([]byte("Something"), HashWithAlgo("sha2-256"), HashWithFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash1 != hash2 {
		t.Error("Error comparing values")
	}

	hash3, err := i.Hash([]byte("Something"), HashWithAlgo("sha2-224"), HashWithFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash3 == hash2 {
		t.Error("Error comparing values")
	}

	hash4, err := i.Hash([]byte("Something"), HashWithAlgo("sha2-224"), HashWithFormat("base64"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash3 == hash4 {
		t.Error("Error comparing values")
	}

	_, err = i.Hash([]byte("Something"), HashWithAlgo("md5"), HashWithFormat("base64"))
	if err == nil {
		t.Error("invalid algo was accepted. error")
	}
}
