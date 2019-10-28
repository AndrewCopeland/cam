package newsafe

import (
	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func Controller(client *conjurapi.Client) {
	safeName := helper.ReadMandatoryArg(1, "safeName", help.NewSafe, "any valid new safe name")

	err := camapi.NewSafe(client, safeName)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
