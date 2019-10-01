package namespace

import (
	"fmt"

	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
	"github.com/karrick/golf"
)

func Controller(client *conjurapi.Client) {
	namespaceName := ""
	if golf.Arg(1) == "" {
		namespaceName, _ = camapi.GetCurrentNamespace()
	}
	if namespaceName == "" {
		namespaceName = helper.ReadMandatoryArg(1, "namespaceName", "", "any valid namespace name")

	}

	err := camapi.OpenNamespace(client, namespaceName)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
	fmt.Println(fmt.Sprintf("Opened namespace '%s'", namespaceName))
}
