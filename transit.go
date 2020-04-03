package transit

import (
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

type Transit struct {
	client     *vaultapi.Client
	EnginePath string
}

func NewTransit(client *vaultapi.Client) *Transit {
	return &Transit{
		client:     client,
		EnginePath: "/transit",
	}
}

func (t *Transit) pathFor3(p1, p2, p3 string) string {
	return fmt.Sprintf("%s/%s/%s/%s", t.EnginePath, p1, p2, p3)
}

func (t *Transit) pathFor2(p1, p2 string) string {
	return fmt.Sprintf("%s/%s/%s", t.EnginePath, p1, p2)
}

func (t *Transit) pathFor1(p1 string) string {
	return fmt.Sprintf("%s/%s", t.EnginePath, p1)
}
