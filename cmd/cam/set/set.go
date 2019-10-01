package set

import (
	"fmt"

	"github.com/AndrewCopeland/cam/cmd/cam/set/app"
	"github.com/AndrewCopeland/cam/cmd/cam/set/namespace"

	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func secret(client *conjurapi.Client, id string, content []byte) error {
	err := client.AddSecret(id, string(content))
	return err
}

func template(client *conjurapi.Client, id string, content []byte) error {
	id = "templates/" + id
	err := client.AddSecret(id, string(content))
	return err
}

func Controller(client *conjurapi.Client) {
	var resource = helper.ReadMandatoryArg(1, "resource", help.Set, "secret", "template", "namespace", "app")

	var err error

	switch resource {
	case "secret":
		id := helper.ReadMandatoryArg(2, "resourceID", help.Set, "any valid id")
		value := helper.ReadMandatoryArg(3, "value", help.Set, "secret value")
		err = secret(client, id, []byte(value))
	case "template":
		id := helper.ReadMandatoryArg(2, "resourceID", help.Set, "any valid id")
		fileName := helper.ReadMandatoryArg(3, "value", help.Set, "template filename")
		value, err := helper.ReadFile(fileName)
		if err != nil {
			err = fmt.Errorf("Failed to read template file '%s'. %s", fileName, err)
		} else {
			err = template(client, id, value)
		}
	case "namespace":
		namespace.Controller(client)
	case "app":
		app.Controller(client)
	}

	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
