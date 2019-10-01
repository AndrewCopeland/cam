package namespace

import (
	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func safe(client *conjurapi.Client, namespaceName string) error {
	var safeName = helper.ReadMandatoryArg(4, "safeName", help.SetNamespace, "any valid safe name")
	err := camapi.SetNamespaceSafe(client, namespaceName, safeName)
	return err
}

func authnIAM(client *conjurapi.Client, namespaceName string) error {
	var serviceID = helper.ReadMandatoryArg(4, "serviceID", help.SetNamespace, "any valid service id")
	err := camapi.SetNamespaceAuthnIAM(client, namespaceName, serviceID)
	return err

}

func authnK8S(client *conjurapi.Client, namespaceName string) error {
	var serviceID = helper.ReadMandatoryArg(4, "serviceID", help.SetNamespace, "any valid service id")
	err := camapi.SetNamespaceAuthnK8S(client, namespaceName, serviceID)
	return err
}

func Controller(client *conjurapi.Client) {
	var namespaceName = helper.ReadMandatoryArg(2, "namespaceName", help.SetNamespace, "any valid namespace name")
	var namespaceAction = helper.ReadMandatoryArg(3, "namespaceAction", help.SetNamespace, "safe", "authn-iam", "authn-k8s")

	// Make sure given namespace actually exists
	err := camapi.FindNamespace(client, namespaceName)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

	switch namespaceAction {
	case "safe":
		err = safe(client, namespaceName)
	case "authn-iam":
		err = authnIAM(client, namespaceName)
	case "authn-k8s":
		err = authnK8S(client, namespaceName)
	}

	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

}
