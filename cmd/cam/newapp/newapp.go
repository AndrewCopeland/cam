package newapp

import (
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func Controller(client *conjurapi.Client) {
	var appName = helper.ReadMandatoryArg(1, "appName", "", "any valid appName name")

	err := camapi.NewApp(client, appName)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
