package transit

import (
	"encoding/base64"
)

// HmacSpec contains hmac parameters
// https://www.vaultproject.io/api/secret/transit/index.html#parameters-11
type HmacSpec struct {
	Algorithm  *string
	KeyVersion *int
}

// HmacSpecOption is a callback setting the appropriate option argument
type HmacSpecOption func(spec *HmacSpec)

// WithHmacAlgo sets an algorithm on a HashSpec
func WithHmacAlgo(algo string) HmacSpecOption {
	return func(spec *HmacSpec) {
		spec.Algorithm = &algo
	}
}

// WithHmacKeyVersion sets the key_version on a HashSpec
func WithHmacKeyVersion(keyVersion int) HmacSpecOption {
	return func(spec *HmacSpec) {
		spec.KeyVersion = &keyVersion
	}
}

// Hmac computes the HMAC from given key, input and options
// https://www.vaultproject.io/api/secret/transit/index.html#generate-hmac
func (t *Transit) Hmac(keyName string, input []byte, opts ...HmacSpecOption) (string, error) {
	spec := &HmacSpec{}
	for _, opt := range opts {
		opt(spec)
	}

	p := t.pathFor2("hmac", keyName)
	if spec.Algorithm != nil {
		p = t.pathFor3("hmac", keyName, *spec.Algorithm)
	}

	var res string
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(input),
	}
	if spec.KeyVersion != nil {
		data["key_version"] = *spec.KeyVersion
	}
	s, err := t.client.Logical().Write(p, data)
	if err != nil {
		return res, err
	}

	if s != nil {
		res = (s.Data)["hmac"].(string)
	}
	return res, err

}

// VerifyHmac verifies an hmac string against the input, given keys and options
// https://www.vaultproject.io/api/secret/transit/index.html#verify-signed-data
func (t *Transit) VerifyHmac(keyName string, input []byte, hmac string, opts ...HmacSpecOption) (bool, error) {
	spec := &HmacSpec{}
	for _, opt := range opts {
		opt(spec)
	}

	p := t.pathFor2("verify", keyName)
	if spec.Algorithm != nil {
		p = t.pathFor3("verify", keyName, *spec.Algorithm)
	}

	var res bool
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(input),
		"hmac":  hmac,
	}
	s, err := t.client.Logical().Write(p, data)
	if err != nil {
		return res, err
	}

	if s != nil {
		res = (s.Data)["valid"].(bool)
	}
	return res, err

}
