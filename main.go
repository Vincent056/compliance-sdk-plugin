// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/hashicorp/go-hclog"
	hplugin "github.com/hashicorp/go-plugin"
	"github.com/oscal-compass/compliance-to-policy-go/v2/plugin"

	"github.com/Vincent056/compliance-sdk-plugin/server"
)

var logger hclog.Logger

func init() {
	logger = hclog.New(&hclog.LoggerOptions{
		Name:       "celscanner-plugin",
		Level:      hclog.Debug,
		Output:     os.Stderr,
		JSONFormat: true,
	})
	hclog.SetDefault(logger)
}

func main() {
	hclog.Default().Info("Starting CELScanner plugin")
	celScannerPlugin := server.New()
	pluginByType := map[string]hplugin.Plugin{
		plugin.PVPPluginName: &plugin.PVPPlugin{Impl: &celScannerPlugin},
	}
	config := plugin.ServeConfig{
		PluginSet: pluginByType,
		Logger:    logger,
	}
	plugin.Register(config)
}
