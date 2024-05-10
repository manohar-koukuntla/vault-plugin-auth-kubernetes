// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"flag"
	"os"

	log "github.com/hashicorp/go-hclog"

	kubeauth "github.com/hashicorp/vault-plugin-auth-kubernetes"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	var ignoreAudienceValidation bool
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}

	cf := flag.NewFlagSet("vault kubernetes settings", flag.ContinueOnError)
	cf.BoolVar(&ignoreAudienceValidation, "ignore-audience-validation", false, "Asking k8s to either ignore audience validation")
	flag.Parse()

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: kubeauth.FactoryFunc(ignoreAudienceValidation),
		// set the TLSProviderFunc so that the plugin maintains backwards
		// compatibility with Vault versions that don’t support plugin AutoMTLS
		TLSProviderFunc: tlsProviderFunc,
	})
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	log.L().Error("plugin shutting down", "error", err)
	os.Exit(1)
}
