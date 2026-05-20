package main

import (
	"eve-forward-auth/types"
	"os"
	"runtime"

	"github.com/charmbracelet/log"
	"github.com/pelletier/go-toml/v2"
)

const Project_version = "alpha0.1"

func main() {
	log.Info("FORWARD AUTH SERVER STARTING", "version", Project_version, "go", runtime.Version())
	configBytes, err := os.ReadFile("./config.toml")
	if err != nil {
		log.Fatal("Could not read config.toml", err)
	}

	var config types.Config

	err = toml.Unmarshal(configBytes, &config)
	if err != nil {
		log.Fatal("Could not parse config.toml", err)
	}

	log.Info("Loaded config",
		"name", config.Name,
		"hosted at", If(config.Server.Is_Secure, "https://", "http://")+config.Server.Domain+"/"+(If(config.Server.Prefix != "", config.Server.Prefix+"/", "")))
}

// TERNARY SUPPORT ?
func If[T any](cond bool, vtrue, vfalse T) T {
	if cond {
		return vtrue
	}
	return vfalse
}
