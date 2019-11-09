package main

import (
	opendistro "github.com/WhizUs/vault-plugin-database-opendistro"
	"github.com/hashicorp/vault/api"
	"log"
	"os"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	if err := opendistro.Run(apiClientMeta.GetTLSConfig()); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
