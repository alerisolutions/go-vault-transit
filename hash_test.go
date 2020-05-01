package transit

import (
	"bytes"
	"testing"
)

func TestHash(t *testing.T) {

	inp := []byte("Something")

	hash1, err := i.Hash(inp)
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	hash2, err := i.Hash(inp, WithHashAlgo("sha2-256"), WithHashFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash1 != hash2 {
		t.Error("Error comparing values")
	}

	hash2r, err := i.HashFromReader(bytes.NewReader(inp), WithHashAlgo("sha2-256"), WithHashFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash stream. error: %s", err)
	}

	if hash2 != hash2r {
		t.Error("Error comparing values")
	}

	hash3, err := i.Hash(inp, WithHashAlgo("sha2-224"), WithHashFormat("hex"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash3 == hash2 {
		t.Error("Error comparing values")
	}

	hash4, err := i.Hash(inp, WithHashAlgo("sha2-224"), WithHashFormat("base64"))
	if err != nil {
		t.Errorf("Unable to hash value. error: %s", err)
	}

	if hash3 == hash4 {
		t.Error("Error comparing values")
	}

	_, err = i.Hash(inp, WithHashAlgo("md5"), WithHashFormat("base64"))
	if err == nil {
		t.Error("invalid algo was accepted. error")
	}
}
