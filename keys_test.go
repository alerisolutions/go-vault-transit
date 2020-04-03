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

func keyCreateUpdateDeleteRun(t *testing.T, keyName, keyType string) {
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

	err = i.DeleteKey(keyName)
	if err != nil {
		t.Errorf("cannot delete %s key: %s error: %s", keyType, keyName, err)
	}

}

func TestCreateUpdateDeleteKey(t *testing.T) {
	keyName := "testkey1"
	keyTypes := []string{"aes128-gcm96", "aes256-gcm96"}

	for _, keyType := range keyTypes {
		keyCreateUpdateDeleteRun(t, keyName, keyType)
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
	tk := os.Getenv("VAULT_ADDR")
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
