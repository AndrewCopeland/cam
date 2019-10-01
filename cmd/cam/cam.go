package main

import (
	"os"

	"github.com/AndrewCopeland/cam/cmd/cam/enable"
	"github.com/AndrewCopeland/cam/cmd/cam/get"
	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/cmd/cam/initialize"
	"github.com/AndrewCopeland/cam/cmd/cam/login"
	"github.com/AndrewCopeland/cam/cmd/cam/namespace"
	"github.com/AndrewCopeland/cam/cmd/cam/newapp"
	"github.com/AndrewCopeland/cam/cmd/cam/newnamespace"
	"github.com/AndrewCopeland/cam/cmd/cam/policy"
	"github.com/AndrewCopeland/cam/cmd/cam/set"
	"github.com/AndrewCopeland/cam/cmd/cam/sync"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/karrick/golf"
	log "github.com/sirupsen/logrus"
)

func handleAction() {
	action := helper.ReadMandatoryArg(0, "action", help.Action, "init", "login", "get", "set", "enable", "sync", "new-namespace", "namespace", "new-app", "policy")

	// login & init is a special use case
	if action == "login" {
		login.Controller()
	} else if action == "init" {
		initialize.Controller()
		os.Exit(0)
	}

	// Create a client and authenticate
	client, err := camapi.Login()
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

	switch action {
	case "get":
		get.Controller(client)
	case "set":
		set.Controller(client)
	case "enable":
		enable.Controller(client)
	case "sync":
		sync.Controller(client)
	case "new-namespace":
		newnamespace.Controller(client)
	case "namespace":
		namespace.Controller(client)
	case "new-app":
		newapp.Controller(client)
	case "policy":
		policy.Controller(client)
	}
}

func main() {
	var _ = golf.BoolP('h', "help", false, "show help")
	var verbose = golf.BoolP('v', "verbose", false, "be verbose")

	golf.Parse()

	log.SetFormatter(&log.TextFormatter{DisableTimestamp: true, DisableLevelTruncation: true})
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	handleAction()
}
