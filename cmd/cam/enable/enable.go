package enable

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func authnIAM(client *conjurapi.Client, serviceID string) error {
	return camapi.EnableAuthnIAM(client, serviceID)
}

func authnK8S(client *conjurapi.Client, serviceID string) error {
	// Make sure authentication service does not exists
	authnID := helper.MakeFullID(client, "webservice", "conjur/authn-k8s/"+serviceID)
	_, err := client.Resource(authnID)
	if err == nil {
		return fmt.Errorf("Authenticaiton service '%s' already exists", authnID)
	}

	// Retrieve the template
	templateID := "templates/enable-authn-k8s.yml"
	templateContent, err := camapi.GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace place holders: SERVICE_ID
	policyContent := bytes.NewReader([]byte(strings.ReplaceAll(string(templateContent), "{{ SERVICE_ID }}", serviceID)))

	// Load policy
	res, err := camapi.Append(client, "root", policyContent, "", false)
	fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append enable authn-k8s policy. %s", err)
	}
	return err
}

func Controller(client *conjurapi.Client) {
	var resource = helper.ReadMandatoryArg(1, "enableAction", help.Enable, "authn-iam", "authn-k8s")
	var serviceID = helper.ReadMandatoryArg(2, "serviceID", help.Enable, "any valid service ID")

	var err error
	switch resource {
	case "authn-iam":
		err = authnIAM(client, serviceID)
	case "authn-k8s":
		err = authnK8S(client, serviceID)
	}

	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
