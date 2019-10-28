package sync

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/AndrewCopeland/cam/cmd/cam/help"

	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/cyberarkapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
	"github.com/labstack/gommon/log"
)

type DAPApp struct {
	Namespace string
	App       string
}

func getAllDAPApplications(pvwaURL string, token string) ([]DAPApp, error) {
	jsonResponse, err := cyberarkapi.ListApplications(pvwaURL, token)
	if err != nil {
		return nil, err
	}

	// iterate through application and select applications that start with DAP_
	// and create these applications within conjur
	applications := jsonResponse["application"].([]interface{})
	var dapApplications []DAPApp

	for _, app := range applications {
		appInterface := app.(map[string]interface{})
		appName := appInterface["AppID"].(string)
		location := appInterface["Location"].(string)

		if strings.HasPrefix(location, "\\Applications\\DAP") {
			location = strings.TrimLeft(location, "\\")
			parts := strings.Split(location, "\\")
			if len(parts) != 3 {
				return nil, fmt.Errorf("Failed to retrieve DAP applications from cyberark. Invalid location '%s'. Location must be '\\Applications\\DAP\\nameSpaceName'", location)
			}
			namespace := parts[2]
			dapApp := DAPApp{
				Namespace: namespace,
				App:       appName}

			dapApplications = append(dapApplications, dapApp)
		}
	}

	return dapApplications, err

}

func getPathAuthenticatorsForApplication(pvwaURL string, token string, appName string) ([][]string, error) {
	// list app authentication methods
	appAuthns, err := cyberarkapi.ListApplicationAuthenticationMethods(pvwaURL, token, appName)
	if err != nil {
		helper.WriteStdErrAndExit(fmt.Errorf("Failed to list application authentation methods for '%s'", appName))
	}

	var authenticationMethods [][]string
	authnMethods := appAuthns["authentication"].([]interface{})

	for _, authMethod := range authnMethods {
		authnInterface := authMethod.(map[string]interface{})
		authnType := authnInterface["AuthType"].(string)
		authnValue := authnInterface["AuthValue"].(string)

		if authnType == "path" {
			parts := strings.Split(authnValue, "/")
			authenticationMethods = append(authenticationMethods, parts)
		}
	}

	return authenticationMethods, err
}

func Application(client *conjurapi.Client, pvwaURL string, token string, dapApp DAPApp) error {
	// Get new app policy from template
	policyReader, err := camapi.GetNewApplicationPolicy(client, dapApp.App)
	if err != nil {
		return err
	}

	// load new-app template for this specific app
	_, err = camapi.Append(client, dapApp.Namespace, policyReader, "", false)
	if err != nil {
		return fmt.Errorf("Failed to load new-namespace policy from template. %s", err)
	}
	fmt.Println(fmt.Sprintf("Successfully loaded application '%s/%s' into conjur", dapApp.Namespace, dapApp.App))

	// now lets get all path authenticators for this specific application
	appAuthenticators, err := getPathAuthenticatorsForApplication(pvwaURL, token, dapApp.App)
	if err != nil {
		return err
	}

	// Iterate through all application auth methods and load into conjur
	for _, appAuthn := range appAuthenticators {
		conjurAuthnType := appAuthn[0]
		switch conjurAuthnType {
		case "iam":
			// Make sure that the path is in correct format iam/serviceID/366637873933/iam-role-name
			if len(appAuthn) != 4 {
				return fmt.Errorf("Invalid DAP path '%s' for example iam/serviceID/366637873933/iam-role-name", strings.Join(appAuthn, "/"))
			}
			// Get the parts from the path
			serviceID := appAuthn[1]
			awsAccount := appAuthn[2]
			iamRoleName := appAuthn[3]

			// Enable iam authenticator in conjur if it does not exsist
			authnID := helper.MakeFullID(client, "webservice", "conjur/authn-iam/"+serviceID)
			if !client.ResourceExists(authnID) {
				err := camapi.EnableAuthnIAM(client, serviceID)
				if err != nil {
					return fmt.Errorf("Failed to enable authn-iam '%s'. %s", serviceID, err)
				}
			}

			// Set this IAM authenticaor for this namespace
			err := camapi.SetNamespaceAuthnIAM(client, dapApp.Namespace, serviceID)
			if err != nil {
				return fmt.Errorf("Failed to set authn-iam '%s' for namespace '%s'. %s", serviceID, dapApp.Namespace, err)
			}

			// Give app access to this authenticator
			err = camapi.SetAppAuthnIAM(client, dapApp.Namespace, dapApp.App, serviceID, awsAccount, iamRoleName)
			if err != nil {
				return fmt.Errorf("Failed to set authenticator authn-iam '%s' for application '%s'. %s", serviceID, dapApp.App, err)
			}

			fmt.Println(fmt.Sprintf("Successfully loaded application authenticator '%s' into conjur", strings.Join(appAuthn, "/")))

			// now we need to get safes app user is member of
			safes, err := cyberarkapi.GetSafesUserIsMemberOf(pvwaURL, token, dapApp.App)
			if err != nil {
				return fmt.Errorf("Failed to list safe members for app '%s'", dapApp.App)
			}
			if len(safes) == 0 {
				return fmt.Errorf("Failed to find safes app '%s' is a member of", dapApp.App)
			}

			for _, safe := range safes {
				// Give namespace access to this safe
				err := camapi.SetNamespaceSafe(client, dapApp.Namespace, safe)
				if err != nil {
					return fmt.Errorf("Failed to give namespace '%s' access to safe '%s'. %s", dapApp.Namespace, safe, err)
				}

				// Give app access to this safe
				err = camapi.SetAppSafe(client, dapApp.Namespace, dapApp.App, safe)
				if err != nil {
					return fmt.Errorf("Failed to give app '%s' access to safe '%s'. %s", dapApp.App, safe, err)
				}

				fmt.Println(fmt.Sprintf("Successfully granted application access to safe '%s' into conjur", safe))
			}
			fmt.Println("-----------------")
		default:
			return fmt.Errorf("Conjur authentication method '%s' is currently not supported", conjurAuthnType)
		}
	}

	return err
}

func Applications(client *conjurapi.Client, pvwaURL string, pvwaUsername string, pvwaPassword string) {
	token, err := cyberarkapi.Authenticate(pvwaURL, pvwaUsername, pvwaPassword)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

	dapApplications, err := getAllDAPApplications(pvwaURL, token)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

	for _, dapApp := range dapApplications {
		err = Application(client, pvwaURL, token, dapApp)
		if err != nil {
			helper.WriteStdErrAndExit(err)
		}

	}
}

func templates(client *conjurapi.Client) ([]string, error) {
	folder := helper.ReadMandatoryArg(2, "templatesFolder", "", "any valid folder containing policy templates")

	// make sure we can read dir/file
	fi, err := os.Stat(folder)
	if err != nil {
		fmt.Println(err)
		return nil, fmt.Errorf("Failed to find '%s'. %s", folder, err)
	}

	// make sure its a directory and not a file
	switch mode := fi.Mode(); {
	case mode.IsRegular():
		return nil, fmt.Errorf("Failed to initilize templates because '%s' is not a direcotry", folder)
	}

	// load the base policy
	content, err := helper.ReadFile(folder + "/init-template.yml")
	if err != nil {
		return nil, fmt.Errorf("Failed to read variable content file '%s'. %s", "init-template.yml", err)
	}
	templatePolicy := bytes.NewReader(content)
	_, err = camapi.Append(client, "root", templatePolicy, "", false)
	if err != nil {
		return nil, fmt.Errorf("Failed to load template policy. %s", err)
	}

	// load the template variables
	files, err := ioutil.ReadDir(folder)
	if err != nil {
		return nil, fmt.Errorf("Failed to read directory. %s", err)
	}

	loadedTemplateVariables := []string{}

	for _, f := range files {
		if !f.IsDir() {

			log.Debug()
			variablePolicy := bytes.NewReader([]byte(fmt.Sprintf("- !variable\r\n  id: %s\r\n  annotations:\r\n    cam: csasatemplatecsasa", f.Name())))

			_, err := camapi.Append(client, "templates", variablePolicy, "", false)
			if err != nil {
				return nil, fmt.Errorf("Failed to load variable policy for variable '%s'. %s", f.Name(), err)
			}

			content, err := helper.ReadFile(folder + "/" + f.Name())
			if err != nil {
				return nil, fmt.Errorf("Failed to read variable content file '%s'. %s", f.Name(), err)
			}
			err = client.AddSecret("templates/"+f.Name(), string(content))
			if err != nil {
				return nil, fmt.Errorf("Failed to load variable content '%s'. %s", f.Name(), err)
			}

			loadedTemplateVariables = append(loadedTemplateVariables, "templates/"+f.Name())
		}
	}

	return loadedTemplateVariables, nil

}

func initCyberarkServiceAccount(client *conjurapi.Client) error {
	// Retrieve the template
	templateID := "templates/cyberark-service-acct.yml"
	templateContent, err := camapi.GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	policyContent := bytes.NewReader(templateContent)
	_, err = camapi.Append(client, "root", policyContent, "", true)
	if err != nil {
		return fmt.Errorf("Failed to load policy for cyberark service account. %s", err)
	}

	// get PVWA Address
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter PVWA Address: ")
	address, _ := reader.ReadString('\n')
	err = client.AddSecret("cyberark/service/pvwaUrl", address)
	if err != nil {
		return err
	}

	fmt.Print("Enter PVWA Username: ")
	username, _ := reader.ReadString('\n')
	err = client.AddSecret("cyberark/service/pvwaUsername", username)
	if err != nil {
		return err
	}

	fmt.Print("Enter PVWA Password: ")
	password, _ := reader.ReadString('\n')
	err = client.AddSecret("cyberark/service/pvwaPassword", password)
	if err != nil {
		return err
	}

	return err

}

func Controller(client *conjurapi.Client) {
	syncAction := helper.ReadMandatoryArg(1, "syncAction", help.Sync, "applications", "application", "templates")

	pvwaURL, err := camapi.GetSecret(client, "cyberark/service/pvwaURL")
	pvwaUsername, err := camapi.GetSecret(client, "cyberark/service/pvwaUsername")
	pvwaPassword, err := camapi.GetSecret(client, "cyberark/service/pvwaPassword")

	// Will want to support append, replace, delete
	switch syncAction {
	case "application":
		if err != nil {
			err = initCyberarkServiceAccount(client)
			if err != nil {
				helper.WriteStdErrAndExit(fmt.Errorf("Failed to init cyberark sevice account. %s", err))
			}
		}

		appName := helper.ReadMandatoryArg(2, "appName", help.Sync, "any valid DAP application name")
		namespace, _ := camapi.GetCurrentNamespace()

		token, err := cyberarkapi.Authenticate(string(pvwaURL), string(pvwaUsername), string(pvwaPassword))
		if err != nil {
			helper.WriteStdErrAndExit(err)
		}

		dapApp := DAPApp{
			Namespace: namespace,
			App:       appName}

		err = Application(client, string(pvwaURL), string(token), dapApp)
		if err != nil {
			helper.WriteStdErrAndExit(err)
		}

	case "applications":
		if err != nil {
			err = initCyberarkServiceAccount(client)
			if err != nil {
				helper.WriteStdErrAndExit(fmt.Errorf("Failed to init cyberark sevice account. %s", err))
			}
		}

		Applications(client, string(pvwaURL), string(pvwaUsername), string(pvwaPassword))
	case "templates":
		loadedTemplates, err := templates(client)
		if err != nil {
			helper.WriteStdErrAndExit(err)
		}
		for _, template := range loadedTemplates {
			fmt.Println(template)
		}
	}
}
