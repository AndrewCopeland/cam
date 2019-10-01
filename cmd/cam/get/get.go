package get

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
	"github.com/karrick/golf"
)

func resources(client *conjurapi.Client) error {
	resources, err := camapi.List(client, nil)

	for _, resource := range resources {
		fmt.Println(resource)
	}

	return err
}

func secret(client *conjurapi.Client) ([]byte, error) {
	secretID := helper.ReadMandatoryArg(2, "secretID", "", "Any valid secret ID")
	version := golf.Arg(3)
	var err error
	var result []byte

	if version == "" {
		result, err = camapi.GetSecret(client, secretID)
	} else {
		versionInt, err := strconv.Atoi(version)
		if err != nil {
			return nil, fmt.Errorf("Invalid version number '%s'. %s", version, err)
		}
		currentVersion := camapi.GetCurrentSecretVersion(client, secretID)
		actualVersion := currentVersion - versionInt

		result, err = camapi.GetSecretVersion(client, secretID, actualVersion)
	}

	return result, err
}

func secrets(client *conjurapi.Client) error {
	resourceFilter := conjurapi.ResourceFilter{Kind: "variable"}
	secrets, err := camapi.List(client, &resourceFilter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve secrets: %s", err)
	}
	for _, secret := range secrets {
		if !strings.Contains(secret, "variable:templates/") {
			fmt.Println(strings.SplitAfterN(secret, ":", 3)[2])
		}
	}
	return err
}

// A template is stored as a secret
func template(client *conjurapi.Client) ([]byte, error) {
	id := helper.ReadMandatoryArg(2, "templateID", "", "any valid template id within the namespace")
	id = "templates/" + id
	result, err := camapi.GetSecret(client, id)

	return []byte(string(result) + "\n"), err
}

// List the templates is slightly different
// All templates have the annotation of cam=csasatemplatecsasa
// All templates the host/user has access to will be listed
func templates(client *conjurapi.Client) error {
	// filter := helper.NewResourceFilter("variable", "template")
	// list(client, filter)

	resourceFilter := conjurapi.ResourceFilter{Kind: "variable", Search: "templates"}
	templates, err := camapi.List(client, &resourceFilter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template: %s", err)
	}
	for _, template := range templates {
		if strings.Contains(template, "variable:templates/") && strings.HasSuffix(template, ".yml") {
			fmt.Println(strings.SplitN(template, "/", 2)[1])
		}
	}
	return err

}

func namespaces(client *conjurapi.Client) error {
	// filter := helper.NewResourceFilter("variable", "template")
	// list(client, filter)

	filter := helper.NewResourceFilter("policy", "namespace")
	namespaces, err := camapi.List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve namespaces: %s", err)
	}

	for _, ns := range namespaces {
		fmt.Println(strings.SplitN(ns, ":", 3)[2])
	}
	return err

}

func namespace(client *conjurapi.Client) error {
	// filter := helper.NewResourceFilter("variable", "template")
	// list(client, filter)
	namespaceName := ""
	// If no namespace was provided fund the current namespace
	if golf.Arg(2) == "" {
		namespaceName, _ = camapi.GetCurrentNamespace()
		if namespaceName == "" {
			helper.ReadMandatoryArg(2, "namespaceName", help.Get, "any valid namespace")
		}
	} else {
		namespaceName = helper.ReadMandatoryArg(2, "namespaceName", help.Get, "any valid namespace")
	}

	// get the authenticators within the namespace
	filter := helper.NewResourceFilter("group", "authn")
	authns, err := camapi.List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve aurthns: %s", err)
	}
	fmt.Println("----- AUTHNS -----")
	for _, authn := range authns {
		if strings.Contains(authn, ":"+namespaceName) {
			parts := strings.Split(authn, "/")
			authnType := parts[len(parts)-2]
			authnName := parts[len(parts)-1]
			fmt.Println("- " + authnType + "/" + authnName)
		}
	}

	// get the safes within the namespace
	filter = helper.NewResourceFilter("group", "safe")
	safes, err := camapi.List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve safes: %s", err)
	}
	fmt.Println("----- SAFES -----")
	for _, safe := range safes {
		if strings.Contains(safe, ":"+namespaceName) {
			parts := strings.Split(safe, "/")
			safeName := parts[len(parts)-1]
			fmt.Println("- " + safeName)
		}
	}

	// get the apps within the namespace
	filter = helper.NewResourceFilter("policy", "app")
	apps, err := camapi.List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve apps: %s", err)
	}
	fmt.Println("----- APPS -----")
	for _, app := range apps {
		if strings.Contains(app, ":"+namespaceName) {
			parts := strings.Split(app, "/")
			appName := parts[len(parts)-1]
			fmt.Println("- " + appName)
		}
	}
	return err

}

func apps(client *conjurapi.Client) error {
	// filter := helper.NewResourceFilter("variable", "template")
	// list(client, filter)

	filter := helper.NewResourceFilter("policy", "app")
	apps, err := camapi.List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve apps: %s", err)
	}

	for _, app := range apps {
		fmt.Println(strings.SplitN(app, ":", 3)[2])
	}
	return err

}

func app(client *conjurapi.Client) error {
	appName := helper.ReadMandatoryArg(2, "appName", help.Get, "any valid application")

	namespaceName, err := camapi.GetCurrentNamespace()
	if err != nil {
		helper.WriteStdErrAndExit(fmt.Errorf("Must open a namespace to get an applications information. %s", err))
	}

	appResponse, err := camapi.GetApp(client, namespaceName, appName)
	if err != nil {
		return fmt.Errorf("Failed to get information about app %s/%s. %s", appResponse.Namespace, appResponse.Namespace, err)
	}
	pprint, _ := json.MarshalIndent(appResponse, "", "  ")
	fmt.Println(string(pprint))

	return err

}

func safes(client *conjurapi.Client) error {
	safes, err := camapi.GetSafes(client)
	if err != nil {
		return fmt.Errorf("Failed to retrieve safes: %s", err)
	}

	for _, safe := range safes {
		fmt.Println(safe)
	}
	return err

}

func authns(client *conjurapi.Client) error {

	filter := conjurapi.ResourceFilter{Kind: "webservice", Search: "conjur"}
	webservices, err := camapi.List(client, &filter)
	if err != nil {
		return fmt.Errorf("Failed to retrieve authenication services: %s", err)
	}

	for _, webservice := range webservices {
		authn := strings.SplitN(webservice, "/", 2)[1]
		fmt.Println(authn)
	}

	return err

}

func Controller(client *conjurapi.Client) {
	var resource = helper.ReadMandatoryArg(1, "resource", help.Get, "secret", "template", "secrets", "templates", "resources", "namespaces", "namespace", "apps", "app", "safes", "authns")
	var response []byte
	var err error

	switch resource {
	case "secret":
		response, err = secret(client)
	case "secrets":
		err = secrets(client)
	case "template":
		response, err = template(client)
	case "templates":
		err = templates(client)
	case "resources":
		err = resources(client)
	case "namespaces":
		err = namespaces(client)
	case "namespace":
		err = namespace(client)
	case "apps":
		err = apps(client)
	case "app":
		err = app(client)
	case "safes":
		err = safes(client)
	case "authns":
		err = authns(client)
	}

	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

	os.Stdout.WriteString(string(response))
}
