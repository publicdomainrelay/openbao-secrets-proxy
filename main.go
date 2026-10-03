package main

import (
	"os"

	"github.com/openbao/openbao/sdk/v2/plugin"

	"github.com/publicdomainrelay/openbao-secrets-proxy/internal/secretsproxy"
)

func main() {
	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: secretsproxy.Factory,
	}); err != nil {
		os.Exit(1)
	}
}
