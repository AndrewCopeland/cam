package app

import (
	"fmt"

	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func safe(client *conjurapi.Client, namespaceName string, appName string) error {
	var safeName = helper.ReadMandatoryArg(4, "safeName", help.SetApp, "any valid safe name")
	err := camapi.SetAppSafe(client, namespaceName, appName, safeName)
	return err
}

func authnIAM(client *conjurapi.Client, namespaceName string, appName string) error {
	var serviceID = helper.ReadMandatoryArg(4, "serviceID", help.SetApp, "any valid service id")
	var awsAccountNumber = helper.ReadMandatoryArg(5, "awsAccountNumber", help.SetApp, "Any calid aws account number")
	var iamRoleName = helper.ReadMandatoryArg(6, "iamRoleName", help.SetApp, "Any valid iam role name")

	err := camapi.SetAppAuthnIAM(client, namespaceName, appName, serviceID, awsAccountNumber, iamRoleName)
	return err

}

func authnK8S(client *conjurapi.Client, namespaceName string, appName string) error {
	var serviceID = helper.ReadMandatoryArg(4, "serviceID", help.SetApp, "any valid service id")
	err := camapi.SetAppAuthnK8S(client, namespaceName, appName, serviceID)
	return err
}

func authn(client *conjurapi.Client, namespaceName string, appName string) error {
	err := camapi.SetAppAuthn(client, namespaceName, appName)
	return err
}

func Controller(client *conjurapi.Client) {
	namespaceName, err := camapi.GetCurrentNamespace()
	if err != nil {
		helper.WriteStdErrAndExit(fmt.Errorf("Must open a namespace to set an application safe or authentication service. %s", err))
	}

	var appName = helper.ReadMandatoryArg(2, "appName", help.SetApp, "any valid app name")
	var appAction = helper.ReadMandatoryArg(3, "appAction", help.SetApp, "safe", "authn", "authn-iam", "authn-k8s")

	// make sure appName is exists
	appID := helper.MakeFullID(client, "policy", namespaceName+"/"+appName)
	_, err = client.Resource(appID)
	if err != nil {
		helper.WriteStdErrAndExit(fmt.Errorf("Application '%s' does not exists or you do not have the correct permissions. %s", appID, err))
	}

	switch appAction {
	case "safe":
		err = safe(client, namespaceName, appName)
	case "authn-iam":
		err = authnIAM(client, namespaceName, appName)
	case "authn-k8s":
		err = authnK8S(client, namespaceName, appName)
	case "authn":
		err = authn(client, namespaceName, appName)
	}

	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
