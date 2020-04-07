package transit

import (
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
)

var (
	i *Transit
)

func keyCycle1(t *testing.T, keyName, keyType string) {
	err := i.CreateKey(keyName, WithType(keyType))
	if err != nil {
		t.Errorf("cannot create %s key: %s error: %s", keyType, keyName, err)
		return
	}

	err = i.UpdateKeyAllowDeletion(keyName)
	if err != nil {
		t.Errorf("cannot update %s key config: %s error: %s", keyType, keyName, err)
		return
	}

	ks, err := i.ReadKey(keyName)
	if err != nil {
		t.Errorf("cannot read %s key config: %s error: %s", keyType, keyName, err)
	}
	if ks == nil {
		t.Errorf("ReadKey returned nil keyspec")
	}
	if ks.KeyType == nil {
		t.Errorf("ReadKey returned nil KeyType in keyspec")
	}
	if *ks.KeyType != keyType {
		t.Errorf("ReadKey returned invalid KeyType in keyspec")
	}

	b, err := i.HasKey(keyName)
	if err != nil {
		t.Errorf("cannot read %s key config: %s error: %s", keyType, keyName, err)
	}
	if b == false {
		t.Errorf("HasKey returned false for existing key")
	}

	err = i.DeleteKey(keyName)
	if err != nil {
		t.Errorf("cannot delete %s key: %s error: %s", keyType, keyName, err)
	}

}

func TestKeyCycle(t *testing.T) {
	keyName := "testkey2"
	keyTypes := []string{"aes128-gcm96", "aes256-gcm96"}

	for _, keyType := range keyTypes {
		keyCycle1(t, keyName, keyType)
	}
}

func TestKeyOptions(t *testing.T) {
	keyName := "k1"
	keyType := "aes256-gcm96"
	err := i.CreateKey(keyName, WithType(keyType), WithConvergentEncryption(), WithDerived())
	if err != nil {
		t.Errorf("cannot create %s key: %s error: %s", keyType, keyName, err)
		return
	}
	err = i.UpdateKeyAllowDeletion(keyName)
	if err != nil {
		t.Errorf("cannot update %s key config: %s error: %s", keyType, keyName, err)
		return
	}

	ks, err := i.ReadKey(keyName)
	if err != nil {
		t.Errorf("cannot read %s key config: %s error: %s", keyType, keyName, err)
	}
	if ks == nil {
		t.Errorf("ReadKey returned nil keyspec")
	}
	if ks.ConvergentEncryption == nil {
		t.Errorf("ReadKey keyspec value is nil")
	}
	if *ks.ConvergentEncryption != true {
		t.Errorf("ReadKey keyspec value is wrong")
	}
	if ks.Derived == nil {
		t.Errorf("ReadKey keyspec value is nil")
	}
	if *ks.Derived != true {
		t.Errorf("ReadKey keyspec value is wrong")
	}

	err = i.DeleteKey(keyName)
	if err != nil {
		t.Errorf("cannot delete %s key: %s error: %s", keyType, keyName, err)
	}

}

func TestList(t *testing.T) {
	keyNames := []string{"testkey1", "testkey2", "testkey3"}
	keyType := "aes256-gcm96"

	for _, keyName := range keyNames {
		err := i.CreateKey(keyName, WithType(keyType))
		if err != nil {
			t.Errorf("cannot create %s key: %s error: %s", keyType, keyName, err)
			return
		}

		err = i.UpdateKeyAllowDeletion(keyName)
		if err != nil {
			t.Errorf("cannot update %s key config: %s error: %s", keyType, keyName, err)
			return
		}
	}

	keys, err := i.ListKeys()
	if err != nil {
		t.Errorf("cannot list keys: %s", err)
	}
	if len(keys) != len(keyNames) {
		t.Errorf("Key lists not equal (len)")
	}

	for _, keyName := range keyNames {
		err := i.DeleteKey(keyName)
		if err != nil {
			t.Errorf("cannot delete %s key: %s error: %s", keyType, keyName, err)
		}
	}
}

func setup() {
	cfg := api.DefaultConfig()
	cfg.ReadEnvironment()

	cfg.Address = os.Getenv("VAULT_ADDR")
	if cfg.Address == "" {
		cfg.Address = "http://127.0.0.1:8200/"
	}
	cfg.HttpClient.Timeout = 10 * time.Second

	client, err := api.NewClient(cfg)
	if err != nil {
		panic(err)
	}
	tk := os.Getenv("VAULT_TOKEN")
	if tk == "" {
		tk = "root"
	}
	client.SetToken(tk)

	i = NewTransit(client)
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	os.Exit(code)
}
