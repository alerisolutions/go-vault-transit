package transit

import (
	"encoding/base64"
)

// HashSpec describes all settings related to hashing
type HashSpec struct {
	Algorithm *string
	Format    *string
}

// HashSpecOption is a callback setting the appropriate option argument
type HashSpecOption func(spec *HashSpec)

// WithHashAlgo sets an algorithm on a HashSpec
func WithHashAlgo(algo string) HashSpecOption {
	return func(spec *HashSpec) {
		spec.Algorithm = &algo
	}
}

// WithHashFormat sets the format on a HashSpec
func WithHashFormat(f string) HashSpecOption {
	return func(spec *HashSpec) {
		spec.Format = &f
	}
}

// Hash computes a hash from given input and options
func (t *Transit) Hash(input []byte, opts ...HashSpecOption) (string, error) {
	spec := &HashSpec{}
	for _, opt := range opts {
		opt(spec)
	}

	p := t.pathFor1("hash")
	if spec.Algorithm != nil {
		p = t.pathFor2("hash", *spec.Algorithm)
	}

	var res string
	data := map[string]interface{}{
		"input": base64.StdEncoding.EncodeToString(input),
	}
	if spec.Format != nil {
		data["format"] = *spec.Format
	}
	s, err := t.client.Logical().Write(p, data)
	if err != nil {
		return res, err
	}

	if s != nil {
		res = (s.Data)["sum"].(string)
	}
	return res, err

}
