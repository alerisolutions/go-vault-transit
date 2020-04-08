package transit

import (
	"encoding/base64"
)

// SignSpec describes all settings related to signing
type SignSpec struct {
	Algorithm  *string
	KeyVersion *int
}

type SignSpecOption func(spec *SignSpec)

// WithSignAlgo sets an algorithm on a SignSpec
func WithSignAlgo(algo string) SignSpecOption {
	return func(spec *SignSpec) {
		spec.Algorithm = &algo
	}
}

// WithkeyVersion sets the key version on a SignSpec
func WithkeyVersion(v int) SignSpecOption {
	return func(spec *SignSpec) {
		spec.KeyVersion = &v
	}
}

// Sign signs the input using the named key and returns the signature
// https://www.vaultproject.io/api/secret/transit/index.html#sign-data
func (t *Transit) Sign(keyName string, input []byte, opts ...SignSpecOption) (string, error) {
	spec := &SignSpec{}
	for _, opt := range opts {
		opt(spec)
	}

	var res string
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(input),
	}
	if spec.Algorithm != nil {
		data["hash_algorithm"] = *spec.Algorithm
	}
	if spec.KeyVersion != nil {
		data["key_version"] = *spec.KeyVersion
	}

	s, err := t.client.Logical().Write(t.pathFor2("sign", keyName), data)
	if err != nil {
		return res, err
	}

	if s != nil {
		res = (s.Data)["signature"].(string)
	}
	return res, err

}

// Verify verifies a signature against the input.
// https://www.vaultproject.io/api/secret/transit/index.html#verify-signed-data
func (t *Transit) Verify(keyName string, input []byte, signature string, opts ...SignSpecOption) (bool, error) {
	spec := &SignSpec{}
	for _, opt := range opts {
		opt(spec)
	}

	var res bool
	data := map[string]interface{}{
		"input":     base64.StdEncoding.EncodeToString(input),
		"signature": signature,
	}
	if spec.Algorithm != nil {
		data["hash_algorithm"] = *spec.Algorithm
	}
	if spec.KeyVersion != nil {
		data["key_version"] = *spec.KeyVersion
	}

	s, err := t.client.Logical().Write(t.pathFor2("verify", keyName), data)
	if err != nil {
		return res, err
	}

	if s != nil {
		r, ex := s.Data["valid"]
		if ex {
			res = r.(bool)
		}
	}
	return res, err

}
