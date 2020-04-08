package transit

import (
	"encoding/base64"
)

// Encrypt encrypts a plaintext using a key. It returns a vault secret.
// https://www.vaultproject.io/api/secret/transit/index.html#encrypt-data
func (t *Transit) Encrypt(keyName string, plaintext []byte) (string, error) {
	var res string
	data := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}
	s, err := t.client.Logical().Write(t.pathFor2("encrypt", keyName), data)
	if err != nil {
		return res, err
	}

	if s != nil {
		res = (s.Data)["ciphertext"].(string)
	}
	return res, err

}

// Decrypt decrypts a vault secret and returns the plaintext
// https://www.vaultproject.io/api/secret/transit/index.html#decrypt-data
func (t *Transit) Decrypt(keyName string, secret string) ([]byte, error) {
	var res []byte
	data := map[string]interface{}{
		"ciphertext": secret,
	}
	s, err := t.client.Logical().Write(t.pathFor2("decrypt", keyName), data)
	if err != nil {
		return res, err
	}

	if s != nil {
		decoded, err := base64.StdEncoding.DecodeString((s.Data)["plaintext"].(string))
		if err != nil {
			return res, err
		}

		res = []byte(decoded)
	}
	return res, err

}
