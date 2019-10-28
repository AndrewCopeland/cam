package newsecret

import (
	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func Controller(client *conjurapi.Client) {
	safeName := helper.ReadMandatoryArg(1, "safeName", help.NewSecret, "any valid safe name")
	secretName := helper.ReadMandatoryArg(2, "secretName", help.NewSecret, "any valid new secret name")
	secretValue := helper.ReadMandatoryArg(3, "secretValue", help.NewSecret, "any secret value")

	err := camapi.NewSecret(client, safeName, secretName, secretValue)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
