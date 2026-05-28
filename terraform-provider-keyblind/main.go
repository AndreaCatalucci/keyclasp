package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/keyblind/terraform-provider-keyblind/internal/provider"
)

func main() {
	err := providerserver.Serve(context.Background(), provider.New, providerserver.ServeOpts{
		Address: "registry.terraform.io/keyblind/keyblind",
	})
	if err != nil {
		log.Fatal(err)
	}
}
