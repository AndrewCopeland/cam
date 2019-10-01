package newnamespace

import (
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func Controller(client *conjurapi.Client) {
	var namespaceName = helper.ReadMandatoryArg(1, "namespaceName", "", "any valid namespace name")

	err := camapi.NewNamespace(client, namespaceName)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
