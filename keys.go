package transit

// KeySpec describes all settings related to a key
type KeySpec struct {
	KeyType              *string
	ConvergentEncryption *bool
	Derived              *bool
	Exportable           *bool
	AllowPlaintextBackup *bool
}

// KeySpecOption sets a single option on given KeySpec
type KeySpecOption func(spec *KeySpec)

var (
	keyOptionTrue = true
)

// WithType Sets the key Type
func WithType(keyType string) KeySpecOption {
	return func(spec *KeySpec) {
		spec.KeyType = &keyType
	}
}

// WithConvergentEncryption enables convergent encryption
func WithConvergentEncryption() KeySpecOption {
	return func(spec *KeySpec) {
		spec.ConvergentEncryption = &keyOptionTrue
	}
}

// WithDerived enables key derivation
func WithDerived() KeySpecOption {
	return func(spec *KeySpec) {
		spec.Derived = &keyOptionTrue
	}
}

// WithExportable enables key export
func WithExportable() KeySpecOption {
	return func(spec *KeySpec) {
		b := true
		spec.Exportable = &b
	}
}

// WithPlaintextBackup allows for plaintext backups
func WithPlaintextBackup() KeySpecOption {
	return func(spec *KeySpec) {
		b := true
		spec.AllowPlaintextBackup = &b
	}
}

// CreateKey creates a new named key using the given key spec options
// https://www.vaultproject.io/api/secret/transit/index.html#create-key
func (t *Transit) CreateKey(keyName string, opts ...KeySpecOption) error {
	spec := &KeySpec{}
	for _, opt := range opts {
		opt(spec)
	}

	data := make(map[string]interface{})
	if spec.KeyType != nil {
		data["type"] = *spec.KeyType
	}
	if spec.ConvergentEncryption != nil {
		data["convergent_encryption"] = *spec.ConvergentEncryption
	}
	if spec.Derived != nil {
		data["derived"] = *spec.Derived
	}
	if spec.Exportable != nil {
		data["exportable"] = *spec.Exportable
	}
	if spec.AllowPlaintextBackup != nil {
		data["allow_plaintext_backup"] = *spec.AllowPlaintextBackup
	}

	_, err := t.client.Logical().Write(t.pathFor2("keys", keyName), data)
	return err
}

// ListKeys lists all keys under engine path
// https://www.vaultproject.io/api/secret/transit/index.html#list-keys
func (t *Transit) ListKeys() ([]string, error) {
	res := make([]string, 0)
	s, err := t.client.Logical().List(t.pathFor1("keys"))
	if s != nil {
		keys := (s.Data)["keys"].([]interface{})
		for _, key := range keys {
			res = append(res, key.(string))
		}
	}
	return res, err
}

// ReadKey reads a single named key
// https://www.vaultproject.io/api/secret/transit/index.html#read-key
func (t *Transit) ReadKey(keyName string) (KeySpec, error) {
	var res KeySpec
	s, err := t.client.Logical().Read(t.pathFor2("keys", keyName))
	if s != nil {
		t, ex := (s.Data)["type"].(string)
		if ex {
			res.KeyType = &t
		}
		b, ex := (s.Data)["convergent_encryption"].(bool)
		if ex {
			res.ConvergentEncryption = &b
		}
		b, ex = (s.Data)["derived"].(bool)
		if ex {
			res.Derived = &b
		}
		b, ex = (s.Data)["exportable"].(bool)
		if ex {
			res.Exportable = &b
		}
		b, ex = (s.Data)["allow_plaintext_backup"].(bool)
		if ex {
			res.AllowPlaintextBackup = &b
		}
	}
	return res, err
}

// HasKey checks if the named key is present
func (t *Transit) HasKey(keyName string) (bool, error) {
	ex := false
	s, err := t.client.Logical().Read(t.pathFor2("keys", keyName))
	if s != nil {
		// todo check for non-empty "keys" map in s.Data
		ex = true
	}
	return ex, err

}

// DeleteKey deletes a named key
// https://www.vaultproject.io/api/secret/transit/index.html#delete-key
func (t *Transit) DeleteKey(keyName string) error {
	_, err := t.client.Logical().Delete(t.pathFor2("keys", keyName))
	return err
}

// UpdateKeyAllowDeletion updates the keys' configuration to allow deletion
// https://www.vaultproject.io/api/secret/transit/index.html#update-key-configuration
func (t *Transit) UpdateKeyAllowDeletion(keyName string) error {
	data := map[string]interface{}{
		"deletion_allowed": true,
	}

	_, err := t.client.Logical().Write(t.pathFor3("keys", keyName, "config"), data)
	return err
}
