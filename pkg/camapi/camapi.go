package camapi

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
	"github.com/labstack/gommon/log"
)

func GetSecret(client *conjurapi.Client, variableID string) ([]byte, error) {
	result, err := client.RetrieveSecret(variableID)
	return result, err
}

func GetSecretVersion(client *conjurapi.Client, variableID string, version int) ([]byte, error) {
	variableID = fmt.Sprintf("%s?version=%d", variableID, version)
	result, err := GetSecret(client, variableID)
	return result, err
}

func GetCurrentSecretVersion(client *conjurapi.Client, variableID string) int {
	version := 0
	resourceID := helper.MakeFullID(client, "variable", variableID)
	resource, err := client.Resource(resourceID)

	// variable resource exists so lets get the most recent version
	if err == nil {
		secretArray := resource["secrets"].([]interface{})
		lastSecret := len(secretArray) - 1
		// jump through hoops to parse version as an int from the 'client.Resource() function. Seems like im doing something wrong
		version = int(secretArray[lastSecret].(map[string]interface{})["version"].(float64))
	}

	return version
}

func GetSetApplicationAuthnIamPolicy(client *conjurapi.Client, appName string, serviceID string, awsAccount string, iamRoleName string) (io.Reader, error) {
	// get the new-app template
	templateName := "templates/set-app-authn-iam.yml"
	log.Debug("set app authn iam template name: " + templateName)
	templateContent, err := GetSecret(client, templateName)
	if err != nil {
		return nil, (fmt.Errorf("Failed to retrieve template '%s'", templateName))
	}

	// replace placeholder in the template
	policyContent := strings.ReplaceAll(string(templateContent), "{{ APP_NAME }}", appName)
	policyContent = strings.ReplaceAll(policyContent, "{{ SERVICE_ID }}", serviceID)
	policyContent = strings.ReplaceAll(policyContent, "{{ AWS_ACCOUNT }}", awsAccount)
	policyContent = strings.ReplaceAll(policyContent, "{{ IAM_ROLE_NAME }}", iamRoleName)

	policyReader := bytes.NewReader([]byte(policyContent))
	return policyReader, err
}

func GetSetAppSafePolicy(client *conjurapi.Client, consumersGroup string, appName string) (io.Reader, error) {
	// get the new-app template
	templateName := "templates/set-app-safe.yml"
	log.Debug("set app safe template name: " + templateName)
	templateContent, err := GetSecret(client, templateName)
	if err != nil {
		return nil, (fmt.Errorf("Failed to retrieve template '%s'", templateName))
	}

	// replace placeholder in the template
	policyContent := strings.ReplaceAll(string(templateContent), "{{ CONSUMERS_GROUP }}", consumersGroup)
	policyContent = strings.ReplaceAll(policyContent, "{{ APP_NAME }}", appName)

	policyReader := bytes.NewReader([]byte(policyContent))
	return policyReader, err
}

func GetSafeConsumersGroup(client *conjurapi.Client, safeName string) (string, error) {
	// Find the delegation group being sync by the VCS
	search := fmt.Sprintf("%s_delegation", safeName)
	resourceFilter := conjurapi.ResourceFilter{Kind: "policy", Search: search}
	resources, err := client.Resources(&resourceFilter)
	if err != nil {
		// fmt.Println(resources)
		return "", fmt.Errorf("Failed to perform resource search with 'policy' and search of '%s'. %s", search, err)
	}

	if len(resources) == 0 {
		return "", fmt.Errorf("Failed to find resource type 'policy' with seach of '%s'", search)
	} else if len(resources) > 1 {
		return "", fmt.Errorf("Found multiple resources that meet criteria for type 'policy' and search '%s'", search)
	}
	consumersGroup := strings.Split(resources[0]["id"].(string), ":")[2] + "/consumers"
	return consumersGroup, err
}

func GetNewApplicationPolicy(client *conjurapi.Client, appName string) (io.Reader, error) {
	// get the new-app template
	templateName := "templates/new-app.yml"
	log.Debug("new app template name: " + templateName)
	templateContent, err := GetSecret(client, templateName)
	if err != nil {
		return nil, (fmt.Errorf("Failed to retrieve template '%s'", templateName))
	}

	// replace placeholder in the template
	policyContent := strings.ReplaceAll(string(templateContent), "{{ APP_NAME }}", appName)
	policyReader := bytes.NewReader([]byte(policyContent))
	return policyReader, err
}

func Login() (*conjurapi.Client, error) {
	config, err := conjurapi.LoadConfig()

	if err != nil {
		err = fmt.Errorf("Failed to load configuration file. %s", err)
		return nil, err
	}

	loginPair, err := conjurapi.LoginPairFromNetRC(config)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch credentials from ~/.netrc. %s", err)
	}

	conjur, err := conjurapi.NewClientFromKey(config, *loginPair)

	_, err = conjur.Authenticate(*loginPair)
	if err != nil {
		err = fmt.Errorf("Failed to authenticate to conjur. %s", err)
		return nil, err
	}

	return conjur, err
}

func List(client *conjurapi.Client, filter *conjurapi.ResourceFilter) ([]string, error) {
	resources, err := client.Resources(filter)
	var resourceIds []string

	if err != nil {
		err = fmt.Errorf("Failed to list resources. %s", err)
		return resourceIds, err
	}

	for _, resource := range resources {
		id := resource["id"].(string)
		resourceIds = append(resourceIds, id)
	}

	return resourceIds, nil
}

func FindNamespace(client *conjurapi.Client, namespaceName string) error {
	filter := helper.NewResourceFilter("policy", "namespace")
	namespaces, err := List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to list namespaces. %s", err)
	}
	for _, ns := range namespaces {
		if strings.HasSuffix(ns, namespaceName) {
			return err
		}
	}
	return fmt.Errorf("Namespace '%s' cannot be found", namespaceName)
}

func FindApp(client *conjurapi.Client, appName string) error {
	namespaceName, err := GetCurrentNamespace()
	if err != nil {
		return err
	}
	filter := helper.NewResourceFilter("policy", "app")
	apps, err := List(client, filter)
	if err != nil {
		return fmt.Errorf("Failed to list apps. %s", err)
	}
	for _, app := range apps {
		if strings.HasSuffix(app, namespaceName+"/"+appName) {
			return err
		}
	}
	return fmt.Errorf("Namespace '%s' cannot be found", appName)
}

func GetCurrentNamespace() (string, error) {
	// Get users home directory
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("Failed to find users current directory. %s", err)
	}

	namespaceFile := usr.HomeDir + "/.conjurnamespace"

	if _, err := os.Stat(namespaceFile); os.IsNotExist(err) {
		return "", fmt.Errorf("Currently not in namespace. To open a namespace perform 'cam namespace testNamespace'")
	}

	content, err := ioutil.ReadFile(namespaceFile)
	if err != nil {
		return "", fmt.Errorf("Failed to read namespace file '%s'", err)
	}

	return string(content), err
}

func GetSafes(client *conjurapi.Client) ([]string, error) {
	filter := conjurapi.ResourceFilter{Kind: "group", Search: "consumers"}
	consumers, err := List(client, &filter)
	var safes []string
	for _, consumer := range consumers {
		if strings.HasSuffix(consumer, "/delegation/consumers") {
			safe := strings.ReplaceAll(consumer, "/delegation/consumers", "")
			parts := strings.Split(safe, "/")
			safe = parts[len(parts)-1]
			safes = append(safes, safe)
		}
	}
	return safes, err
}

func SetNamespaceAuthnIAM(client *conjurapi.Client, namespaceName string, serviceID string) error {
	// make sure service ID exists
	authnID := helper.MakeFullID(client, "webservice", "conjur/authn-iam/"+serviceID)
	_, err := client.Resource(authnID)
	if err != nil {
		return fmt.Errorf("Authentication service '%s' cannot be found or you do not have the correct permissions. %s", authnID, err)
	}

	// Retrieve the template
	templateID := "templates/set-namespace-authn-iam.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the set-namespace-authn-iam policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ NAMESPACE }}", namespaceName)
	policyString = strings.ReplaceAll(policyString, "{{ SERVICE_ID }}", serviceID)
	policyContent := bytes.NewReader([]byte(policyString))
	_, err = Append(client, "root", policyContent, "", false)
	// fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append set namespace safe policy. %s", err)
	}

	return err
}

func SetNamespaceAuthnK8S(client *conjurapi.Client, namespaceName string, serviceID string) error {
	// make sure service ID exists
	authnID := helper.MakeFullID(client, "webservice", "conjur/authn-k8s/"+serviceID)
	_, err := client.Resource(authnID)
	if err != nil {
		return fmt.Errorf("Authentication service '%s' cannot be found or you do not have the correct permissions. %s", authnID, err)
	}

	// Retrieve the template
	templateID := "templates/set-namespace-authn-k8s.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the set-namespace-authn-iam policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ NAMESPACE }}", namespaceName)
	policyString = strings.ReplaceAll(policyString, "{{ SERVICE_ID }}", serviceID)
	policyContent := bytes.NewReader([]byte(policyString))
	res, err := Append(client, "root", policyContent, "", false)
	fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append set namespace safe policy. %s", err)
	}

	return err
}

func SetNamespaceSafe(client *conjurapi.Client, namespaceName string, safeName string) error {
	// Retrieve the template
	templateID := "templates/set-namespace-safe.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Get all consumers group and make sure consumers group exists for this safe
	filter := conjurapi.ResourceFilter{Kind: "group", Search: "consumers"}
	consumerGroups, err := List(client, &filter)
	if err != nil {
		return fmt.Errorf("Failed to list consumer groups. %s", err)
	}
	consumersGroup := ""
	for _, consumer := range consumerGroups {
		if strings.HasSuffix(consumer, "/"+safeName+"/delegation/consumers") {
			consumersGroup = strings.SplitN(consumer, ":", 3)[2]
		}
	}

	// Consumers group cannot be found
	if consumersGroup == "" {
		return fmt.Errorf("Failed to find consumers group for safe '%s'. Either you do not have permissions or this safe is not being synced into DAP", safeName)
	}

	// Replace the placeholders and load the set-namespace-safe policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ NAMESPACE }}", namespaceName)
	policyString = strings.ReplaceAll(policyString, "{{ SAFE_NAME }}", safeName)
	policyString = strings.ReplaceAll(policyString, "{{ CONSUMERS_GROUP }}", consumersGroup)
	policyContent := bytes.NewReader([]byte(policyString))
	_, err = Append(client, "root", policyContent, "", false)
	// fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append set namespace safe policy. %s", err)
	}

	return err
}

func UpdatePolicyVariable(client *conjurapi.Client, policyBranch string, policyContent io.Reader, appendPolicy bool) error {
	// create policy IDs
	policyVariableID := helper.GetPolicyVariableID(policyBranch)
	fullPolicyVariableID := helper.GetFullPolicyVariableID(client, policyBranch)

	// make sure policy variable actually exists
	_, err := client.Resource(fullPolicyVariableID)

	// policy variable does not exists lets create it
	if err != nil {
		policyVariablePolicy := bytes.NewReader([]byte("- !variable policy"))

		// create the policy variable resource
		_, err = Append(client, policyBranch, policyVariablePolicy, "", true)
		if err != nil {
			err = fmt.Errorf("Failed to create policy variable. %s", err)
			return err
		}

		// make sure there is no value in the policy variable
		_, err = GetSecret(client, policyVariableID)
		if err != nil {
			// init the variable
			err = client.AddSecret(policyVariableID, "blank")

			if err != nil {
				err = fmt.Errorf("Failed to init policy variable.  %s", err)
				return err
			}
		}
	}

	var currentPolicyContent []byte

	// Make sure we can read the policy content we are appending
	newPolicyContent, err := ioutil.ReadAll(policyContent)
	if err != nil {
		return fmt.Errorf("Failed to read new policy file. %s", err)
	}

	if appendPolicy {
		// Get the current policy variable content
		currentPolicyContent, err = GetSecret(client, policyVariableID)
		if err != nil {
			return fmt.Errorf("Failed to get the current policy variable. %s", err)
		}
		if string(currentPolicyContent) == "blank" {
			currentPolicyContent = []byte("")
		}

		currentPolicyContent = append(currentPolicyContent, newPolicyContent...)
	} else {
		// assuming replacing the policy variable.
		// don't really know how to deal with delete.
		// I would recommend replacing with policy with resource removed or rolling back (thats a work around).
		currentPolicyContent = newPolicyContent
	}

	// set the policy to the policy variable
	err = client.AddSecret(policyVariableID, string(currentPolicyContent))
	if err != nil {
		err = fmt.Errorf("Failed to set policy variable to desired. %s", err)
	}

	return err
}

func Append(client *conjurapi.Client, policyBranch string, policyContent io.Reader, policyFilePath string, ignorePolicyVariable bool) (*conjurapi.PolicyResponse, error) {
	policyByte, err := ioutil.ReadAll(policyContent)

	policyContent = bytes.NewReader(policyByte)
	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePost, policyBranch, policyContent)

	// If policy load was successful store the newly appended policy to the policy variable within the policy branch
	if err == nil && ignorePolicyVariable == false {
		policyContent = bytes.NewReader(policyByte)
		err = UpdatePolicyVariable(client, policyBranch, policyContent, true)
		if err != nil {
			return nil, err
		}
	}
	return policyResponse, err
}

func Replace(client *conjurapi.Client, policyBranch string, policyContent io.Reader, policyFilePath string, ignorePolicyVariable bool) (*conjurapi.PolicyResponse, error) {
	policyByte, err := ioutil.ReadAll(policyContent)

	policyContent = bytes.NewReader(policyByte)
	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePut, policyBranch, policyContent)

	if err != nil {
		err = fmt.Errorf("Failed to replace policy. %s", err)
	}

	// If policy load was successful store the newly replaces policy to the policy variable within the policy branch
	if err == nil && ignorePolicyVariable == false {
		policyContent = bytes.NewReader(policyByte)
		err = UpdatePolicyVariable(client, policyBranch, policyContent, false)
		if err != nil {
			return nil, err
		}
	}
	return policyResponse, err
}

func Rollback(client *conjurapi.Client, policyBranch string, version int) (*conjurapi.PolicyResponse, error) {
	policyVariableID := helper.GetPolicyVariableID(policyBranch)
	currentVersion := GetCurrentSecretVersion(client, policyVariableID)
	actualVersion := currentVersion - version

	policyContent, err := GetSecretVersion(client, policyVariableID, actualVersion)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch policy variable to perform rollback. %s", err)
	}
	policy := bytes.NewReader(policyContent)

	policyResponse, err := Replace(client, policyBranch, policy, "", false)
	if err != nil {
		err = fmt.Errorf("Failed to replace policy when performing a rollback. %s", err)
	}

	return policyResponse, err
}

func NewApp(client *conjurapi.Client, appName string) error {
	// Make sure application does not exists
	err := FindApp(client, appName)
	if err == nil {
		return fmt.Errorf("Failed to create app '%s' because it already exists", appName)
	}

	// Make sure we are in a namespace
	namespace, err := GetCurrentNamespace()
	if err != nil {
		return err
	}

	// Retrieve the template
	templateID := "templates/new-app.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the new-app policy
	policyContent := bytes.NewReader([]byte(strings.ReplaceAll(string(templateContent), "{{ APP_NAME }}", appName)))
	res, err := Append(client, namespace, policyContent, "", false)
	fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append app policy. %s", err)
	}
	return err
}

func OpenNamespace(client *conjurapi.Client, namespaceName string) error {
	// Make sure namespace exists
	err := FindNamespace(client, namespaceName)
	if err != nil {
		return err
	}

	// Get users home directory
	usr, err := user.Current()
	if err != nil {
		return fmt.Errorf("Failed to find users current directory. %s", err)
	}

	// write namespace to the namespace file
	namespaceFile := usr.HomeDir + "/.conjurnamespace"
	content := []byte(namespaceName)
	err = ioutil.WriteFile(namespaceFile, content, 0644)
	if err != nil {
		return fmt.Errorf("Failed to create namespace file '%s'. %s", namespaceFile, err)
	}
	return err
}

func NewNamespace(client *conjurapi.Client, namespaceName string) error {
	err := FindNamespace(client, namespaceName)
	if err == nil {
		return fmt.Errorf("Failed to create namespace '%s' because it already exists", namespaceName)
	}

	// Retrieve the template
	templateID := "templates/new-namespace.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the new-namespace policy
	policyContent := bytes.NewReader([]byte(strings.ReplaceAll(string(templateContent), "{{ NAMESPACE }}", namespaceName)))
	res, err := Append(client, "root", policyContent, "", false)
	fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append namespace policy. %s", err)
	}
	return err
}

func SetAppAuthnIAM(client *conjurapi.Client, namespaceName string, appName string, serviceID string, accountNumber string, iamRoleName string) error {
	// make sure service ID exists
	authnID := helper.MakeFullID(client, "group", namespaceName+"/authns/iam/"+serviceID)
	_, err := client.Resource(authnID)
	if err != nil {
		return fmt.Errorf("Authentication service '%s' cannot be found or you do not have the correct permissions. %s", authnID, err)
	}

	// Retrieve the template
	templateID := "templates/set-app-authn-iam.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the set-namespace-authn-iam policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ APP_NAME }}", appName)
	policyString = strings.ReplaceAll(policyString, "{{ SERVICE_ID }}", serviceID)
	policyString = strings.ReplaceAll(policyString, "{{ AWS_ACCOUNT }}", accountNumber)
	policyString = strings.ReplaceAll(policyString, "{{ IAM_ROLE_NAME }}", iamRoleName)
	policyContent := bytes.NewReader([]byte(policyString))
	_, err = Append(client, namespaceName, policyContent, "", false)
	// fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append set namespace safe policy. %s", err)
	}

	return err
}

func SetAppAuthnK8S(client *conjurapi.Client, namespaceName string, appName string, serviceID string) error {
	// make sure service ID exists
	authnID := helper.MakeFullID(client, "webservice", "conjur/authn-k8s/"+serviceID)
	_, err := client.Resource(authnID)
	if err != nil {
		return fmt.Errorf("Authentication service '%s' cannot be found or you do not have the correct permissions. %s", authnID, err)
	}

	// Retrieve the template
	templateID := "templates/set-namespace-authn-k8s.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the set-namespace-authn-iam policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ NAMESPACE }}", namespaceName)
	policyString = strings.ReplaceAll(policyString, "{{ SERVICE_ID }}", serviceID)
	policyContent := bytes.NewReader([]byte(policyString))
	res, err := Append(client, "root", policyContent, "", false)
	fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append set namespace safe policy. %s", err)
	}

	return err
}

func SetAppAuthn(client *conjurapi.Client, namespaceName string, appName string) error {
	// Only set app authn if app exists
	hostID := helper.MakeFullID(client, "host", namespaceName+"/"+appName)
	if client.ResourceExists(hostID) {
		return fmt.Errorf("Application api key '%s' already exists", hostID)
	}

	// Retrieve the template
	templateID := "templates/set-app-authn.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the set-app-safe policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ APP_NAME }}", appName)
	policyContent := bytes.NewReader([]byte(policyString))
	res, err := Append(client, namespaceName, policyContent, "", false)
	// fmt.Println(helper.JsonPrettyPrint(res))
	fmt.Println(fmt.Sprintf("API Key generated for application '%s'", appName))
	fmt.Println(fmt.Sprintf("Authenticator ID: host/%s/%s", namespaceName, appName))
	fmt.Println(fmt.Sprintf("Get api_key by executing 'cam get secret %s/%s/api_key'", namespaceName, appName))

	apiKey := res.CreatedRoles[hostID].APIKey
	if err != nil {
		return fmt.Errorf("Failed to append set app safe policy. %s", err)
	}

	apiKeyID := helper.MakeFullID(client, "variable", fmt.Sprintf("%s/%s/api_key", namespaceName, appName))
	err = client.AddSecret(apiKeyID, apiKey)
	if err != nil {
		return fmt.Errorf("Failed to set apiKey '%s' for app. %s", apiKeyID, err)
	}

	return err
}

type AppResponse struct {
	Namespace      string
	App            string
	Safes          []string
	Authenticators []string
	ApiKey         string
}

func GetApp(client *conjurapi.Client, namespaceName string, appName string) (AppResponse, error) {
	appResponse := AppResponse{
		Namespace: namespaceName,
		App:       appName}

	filter := helper.NewResourceFilter("policy", "app")
	apps, err := List(client, filter)
	if err != nil {
		return appResponse, fmt.Errorf("Failed to retrieve apps: %s", err)
	}
	for _, app := range apps {
		if strings.HasSuffix(app, namespaceName+"/"+appName) {
			safesID := strings.ReplaceAll(app+"/safes", ":policy:", ":group:")
			safes, err := client.Memberships(safesID)
			if err != nil {
				return appResponse, fmt.Errorf("Failed to retrieve app safes '%s'. %s", app, err)
			}
			for _, safe := range safes {
				if strings.Contains(safe, ":group:"+namespaceName+"/safes") {
					safeID := strings.SplitN(safe, ":", 3)[2]
					safeID = strings.SplitN(safeID, "/", 3)[2]
					appResponse.Safes = append(appResponse.Safes, safeID)
				}
			}

			authnsID := strings.ReplaceAll(app+"/authns", ":policy:", ":group:")
			authns, err := client.Members(authnsID)
			if err != nil {
				return appResponse, fmt.Errorf("Failed to retrieve app authns'%s' . %s", app, err)
			}
			for _, authn := range authns {
				if strings.Contains(authn.Member, ":host:") {
					authnID := strings.SplitN(authn.Member, ":", 3)[2]
					appResponse.Authenticators = append(appResponse.Authenticators, "host/"+authnID)
				}
			}
		}
	}

	return appResponse, err
}

func SetAppSafe(client *conjurapi.Client, namespaceName string, appName string, safeName string) error {
	// make sure safe exists
	authnID := helper.MakeFullID(client, "group", namespaceName+"/safes/"+safeName)
	_, err := client.Resource(authnID)
	if err != nil {
		return fmt.Errorf("Safe '%s' cannot be found or you do not have the correct permissions. %s", authnID, err)
	}

	// Retrieve the template
	templateID := "templates/set-app-safe.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace the placeholders and load the set-app-safe policy
	policyString := strings.ReplaceAll(string(templateContent), "{{ APP_NAME }}", appName)
	policyString = strings.ReplaceAll(policyString, "{{ SAFE_NAME }}", safeName)
	policyContent := bytes.NewReader([]byte(policyString))
	_, err = Append(client, namespaceName, policyContent, "", false)
	// fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append set app safe policy. %s", err)
	}

	return err
}

func EnableAuthnIAM(client *conjurapi.Client, serviceID string) error {
	// Make sure authentication service does not exists
	authnID := helper.MakeFullID(client, "webservice", "conjur/authn-iam/"+serviceID)
	_, err := client.Resource(authnID)
	if err == nil {
		return fmt.Errorf("Authenticaiton service '%s' already exists", authnID)
	}

	// Retrieve the template
	templateID := "templates/enable-authn-iam.yml"
	templateContent, err := GetSecret(client, templateID)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'. %s", templateID, err)
	}

	// Replace place holders: SERVICE_ID
	policyContent := bytes.NewReader([]byte(strings.ReplaceAll(string(templateContent), "{{ SERVICE_ID }}", serviceID)))

	// Load policy
	_, err = Append(client, "root", policyContent, "", false)
	// fmt.Println(helper.JsonPrettyPrint(res))
	if err != nil {
		return fmt.Errorf("Failed to append enable authn-iam policy. %s", err)
	}
	return err
}
