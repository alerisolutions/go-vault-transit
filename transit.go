package transit

import (
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"
)

// Transit wraps the vault api client with a path being the entry
// point to the transit engine.
type Transit struct {
	client     *vaultapi.Client
	EnginePath string
}

// NewTransit creates a new transit client struct with a default engine path of /transit
func NewTransit(client *vaultapi.Client) *Transit {
	return NewTransitWithPath(client, "/transit")
}

//NewTransitWithPath creates a new transit client struct with an individual engine path
func NewTransitWithPath(client *vaultapi.Client, pathToTransitEngine string) *Transit {
	return &Transit{
		client:     client,
		EnginePath: pathToTransitEngine,
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
