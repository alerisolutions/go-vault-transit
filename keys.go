package transit

type KeySpec struct {
	KeyType              *string
	ConvergentEncryption *bool
	Derived              *bool
}

type KeySpecOption func(spec *KeySpec)

func WithType(keyType string) KeySpecOption {
	return func(spec *KeySpec) {
		spec.KeyType = &keyType
	}
}

func WithConvergentEncryption() KeySpecOption {
	return func(spec *KeySpec) {
		b := true
		spec.ConvergentEncryption = &b
	}
}

func WithDerived() KeySpecOption {
	return func(spec *KeySpec) {
		b := true
		spec.Derived = &b
	}
}

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

	_, err := t.client.Logical().Write(t.pathFor2("keys", keyName), data)
	return err
}

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
	}
	return res, err
}

func (t *Transit) HasKey(keyName string) (bool, error) {
	ex := false
	s, err := t.client.Logical().Read(t.pathFor2("keys", keyName))
	if s != nil {
		// check for non-empty "keys" map in s.Data
		ex = true
	}
	return ex, err

}

func (t *Transit) DeleteKey(keyName string) error {
	_, err := t.client.Logical().Delete(t.pathFor2("keys", keyName))
	return err
}

func (t *Transit) UpdateKeyAllowDeletion(keyName string) error {
	data := map[string]interface{}{
		"deletion_allowed": true,
	}

	_, err := t.client.Logical().Write(t.pathFor3("keys", keyName, "config"), data)
	return err
}
