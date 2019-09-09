package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/karrick/golf"
	log "github.com/sirupsen/logrus"
)

// ammteam

// Templates
// !policy ammteam/templates/
// !variable ammteam/templates/new-app.yml
// !variable ammteam/templates/set-app-authn.yml
// !variable ammteam/templates/set-app-authn-iam.yml
// !variable ammteam/templates/set-app-authn-k8s.yml
// !variable ammteam/templates/set-app-safe.yml

// Safes
// !policy aamteam/safes
// !group aamteam/safes/my-app-ro
// !group aamteam/safes/my-app-rw
// !group aamteam/safes/my-app-w
// TODO: Still havent implented r, w, e safes

// Authenticators
// !policy ammteam/authns
// !policy ammteam/authns/iam
// !policy ammteam/authns/k8s
// !group ammteam/authns/k8s/serviceID

// Apps
// !policy ammteam/my-app
// !group aamteam/my-app/safes
// !group aapteam/my-app/authns
// !host ammteam/my-app/665775774884775/iam-role-name
// !host aamteam/my-app/aamteam.my-app.company.local

// UX

// CONJUR ADMIN: the conjur admin will give namespaces access to authenticators & safes
// $ cam new-namespace aamteam
// $ cam set namespace aamteam safe DEV_AAMTEAM
// $ cam set namespace aamteam safe DEV_AAMTEAM --read --write

// If the authentator does not exists then create the authentcator and link it to the aamteam namespace
// $ cam set namespace aamteam authn iam prod

// DEVELOPER/DEVELOPER PIPELINE: the developer will give specific app access to safes and authenticators based off what the CONJUR ADMIN gave them rights too
// $ cam namespace aamteam
// $ cam new-app my-app

// This will abstact the hosts and authentictors
// what will happen is a host will be created in 'my-app' that will have the id of
// 'aamteam/my-app/7477488399383/conjur-iam-role' then this host will automatically be added to the 'aamteam/my-app/authns' group.
// user ends up just thinking they enabled an authenticator for their application
// $ cam set app my-app authn iam --service prod --account 7477488399383 --role conjur-iam-role

// user gives application (in turn all configured authenticators) permissions to the safe
// it will default to read and execute however this should be able to be overridden by a flag such as '--write' (this may not be possible to all safes since the conjur admin give the namespace access to safes)
// maybe each namespace should have its own 'default' safe where application managers can store short lived secrets or only secrets that apply to there applications/microservices
// $ cam set app my-app safe DEV_AAMTEAM
// $ cam set app my-app safe DEV_AAMTEAM --read --write

// ######################################
// # helper functions
// ######################################
func logErrorAndReturnError(message string, err error) error {
	msg := message + fmt.Sprintf(" %s\n", err)
	log.Errorf(msg)
	err = fmt.Errorf(msg)
	return err
}

func writeStdErrAndExit(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}

func newResourceFilter(kind string, annotation string) *conjurapi.ResourceFilter {
	// sandwiching annotation with csasa making querying much easier
	annotation = "csasa" + annotation + "csasa"
	resourceFilter := conjurapi.ResourceFilter{Kind: kind, Search: annotation}
	return &resourceFilter
}

func getIoReader(fileName string) (io.Reader, error) {
	file, err := os.Open(fileName)
	return file, err
}

func getPolicyVariableID(policyBranch string) string {
	// Create policy ID
	policyVariableID := "policy"
	if policyBranch != "root" {
		policyVariableID = policyBranch + "/" + policyVariableID
	}
	return policyVariableID

}

func getFullPolicyVariableID(client *conjurapi.Client, policyBranch string) string {
	policyVariableID := getPolicyVariableID(policyBranch)
	policyVariableID = makeFullID(client, "variable", policyVariableID)
	return policyVariableID
}

func readMandatoryArg(index int, name string, validArguments ...string) string {
	result := golf.Arg(index)
	if result == "" {
		err := fmt.Errorf("Mandatory argument '%s' is required. Valid arguments are '%s'", name, strings.Join(validArguments, ", "))
		writeStdErrAndExit(err)
	}
	return result
}

func readFile(fileName string) ([]byte, error) {
	file, err := getIoReader(fileName)
	if err != nil {
		return nil, err
	}

	value, err := ioutil.ReadAll(file)
	return value, err
}

func makeFullID(client *conjurapi.Client, kind string, id string) string {
	tokens := strings.SplitN(id, ":", 3)
	switch len(tokens) {
	case 1:
		tokens = []string{client.GetConfig().Account, kind, tokens[0]}
	case 2:
		tokens = []string{client.GetConfig().Account, tokens[0], tokens[1]}
	}
	return strings.Join(tokens, ":")
}

func getHomeDirectory() (string, error) {
	// get users home directory
	usr, err := user.Current()
	if err != nil {
		return "", errors.New("Failed to find user's home directory")
	}
	return usr.HomeDir, err
}

func getNamespaceLocation(namespaceName string) (string, error) {
	// get home directory
	homeDir, err := getHomeDirectory()
	return fmt.Sprintf("%s/.cam.namespace", homeDir), err
}

func writeNamespaceLocation(namespaceName string) error {
	// get namespace file name in home directory
	namespaceFileName, err := getNamespaceLocation(namespaceName)
	if err != nil {
		return err
	}

	// write to conjur namespace file
	data := []byte(namespaceName)
	err = ioutil.WriteFile(namespaceFileName, data, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write namespace file '%s'. %s", namespaceFileName, err)
	}

	return err
}

// ######################################
// # login action
// ######################################
func login() (*conjurapi.Client, error) {
	config, err := conjurapi.LoadConfig()

	if err != nil {
		err = logErrorAndReturnError("Failed to load configuration file.", err)
		return nil, err
	}

	loginPair := authn.LoginPair{
		Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
		APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
	}

	conjur, err := conjurapi.NewClientFromKey(config, loginPair)

	if err != nil {
		err = logErrorAndReturnError("Failed to authenticate to conjur.", err)
		return nil, err
	}

	_, err = conjur.Authenticate(loginPair)

	return conjur, err
}

// ######################################
// # get action
// ######################################
// will return the current version of a variable being used.
// will return 0 if current version cannot be found
func getCurrentSecretVersion(client *conjurapi.Client, variableID string) int {
	version := 0
	resourceID := makeFullID(client, "variable", variableID)
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

func GetSecretVersion(client *conjurapi.Client, variableID string, version int) ([]byte, error) {
	variableID = fmt.Sprintf("%s?version=%d", variableID, version)
	fmt.Println(variableID)
	result, err := client.RetrieveSecret(variableID)
	return result, err
}

func GetSecret(client *conjurapi.Client, variableID string) ([]byte, error) {
	result, err := client.RetrieveSecret(variableID)
	return result, err
}

func getSecret(client *conjurapi.Client) ([]byte, error) {
	secretID := readMandatoryArg(2, "secretID", "Any valid secret ID")
	version := golf.Arg(3)
	var err error
	var result []byte

	if version == "" {
		result, err = GetSecret(client, secretID)
	} else {
		versionInt, err := strconv.Atoi(version)
		if err != nil {
			return nil, fmt.Errorf("Invalid version number '%s'. %s", version, err)
		}
		currentVersion := getCurrentSecretVersion(client, secretID)
		actualVersion := currentVersion - versionInt

		result, err = GetSecretVersion(client, secretID, actualVersion)
	}

	if err != nil {
		err = logErrorAndReturnError(fmt.Sprintf("Failed to retrieve secret '%s'.", secretID), err)
		return nil, err
	}

	return result, err
}

// A template is stored as a secret
func getTemplate(client *conjurapi.Client) ([]byte, error) {
	id := readMandatoryArg(2, "templateID", "any valid template id within the namespace")
	id = "templates/" + id
	result, err := GetSecret(client, id)
	return result, err
}

// List the templates is lsightly different
// All templates have the annotation of cam=csasatemplatecsasa
// All templates the host/user has access to will be listed
func getTemplates(client *conjurapi.Client) {
	filter := newResourceFilter("variable", "template")
	list(client, filter)
}

// Get a resource
func getController(client *conjurapi.Client) {
	var resource = readMandatoryArg(1, "resource", "secret", "template", "templates")
	var response []byte
	var err error

	switch resource {
	case "secret":
		response, err = getSecret(client)
	case "template":
		response, err = getTemplate(client)
	case "templates":
		getTemplates(client)
	}

	if err != nil {
		writeStdErrAndExit(err)
	}

	os.Stdout.WriteString(string(response))
}

// ######################################
// # set action
// ######################################
func setSecret(client *conjurapi.Client, id string, content []byte) error {
	err := client.AddSecret(id, string(content))
	return err
}

func setTemplate(client *conjurapi.Client, id string, content []byte) error {
	id = "templates/" + id
	err := client.AddSecret(id, string(content))
	return err
}

func setController(client *conjurapi.Client) {
	var resource = os.Args[2]
	id := os.Args[3]
	fileName := os.Args[4]
	value, err := readFile(fileName)

	switch resource {
	case "secret":
		err = setSecret(client, id, value)
	case "template":
		err = setTemplate(client, id, value)
	}

	if err != nil {
		writeStdErrAndExit(err)
	}
}

// ######################################
// # list action
// ######################################
func list(client *conjurapi.Client, filter *conjurapi.ResourceFilter) (string, error) {
	resources, err := client.Resources(filter)

	if err != nil {
		err = logErrorAndReturnError("Failed to list resources.", err)
		return "", err
	}

	for _, resource := range resources {
		fmt.Println(resource["id"])
	}

	return "", nil
}

func listController(client *conjurapi.Client) {
	list(client, nil)
}

// ######################################
// # policy action
// ######################################
func policyUpdatePolicyVariable(client *conjurapi.Client, policyBranch string, policyContent io.Reader, appendPolicy bool) error {
	// create policy IDs
	policyVariableID := getPolicyVariableID(policyBranch)
	fullPolicyVariableID := getFullPolicyVariableID(client, policyBranch)

	// make sure policy variable actually exists
	_, err := client.Resource(fullPolicyVariableID)

	// policy variable does not exists lets create it
	if err != nil {
		policyVariablePolicy := bytes.NewReader([]byte("- !variable policy"))

		// create the policy variable resource
		_, err = policyAppend(client, policyBranch, policyVariablePolicy, "", true)
		if err != nil {
			err = fmt.Errorf("Failed to create policy variable. %s", err)
			return err
		}

		// make sure there is no value in the policy variable
		// the reason why we do this is because variable contents persist even after the resource is removed (which happens during a replace)
		_, err = GetSecret(client, policyVariableID)
		if err != nil {
			// init the variable
			err = setSecret(client, policyVariableID, []byte("blank"))
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
	err = setSecret(client, policyVariableID, currentPolicyContent)
	if err != nil {
		err = fmt.Errorf("Failed to set policy variable to desired. %s", err)
	}

	return err
}

func policyAppend(client *conjurapi.Client, policyBranch string, policyContent io.Reader, policyFilePath string, ignorePolicyVariable bool) (*conjurapi.PolicyResponse, error) {
	policyByte, err := ioutil.ReadAll(policyContent)

	policyContent = bytes.NewReader(policyByte)
	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePost, policyBranch, policyContent)

	// If policy load was successful store the newly appended policy to the policy variable within the policy branch
	if err == nil && ignorePolicyVariable == false {
		policyContent = bytes.NewReader(policyByte)
		err = policyUpdatePolicyVariable(client, policyBranch, policyContent, true)
		if err != nil {
			return nil, err
		}
	}
	return policyResponse, err
}

func policyReplace(client *conjurapi.Client, policyBranch string, policyContent io.Reader, policyFilePath string, ignorePolicyVariable bool) (*conjurapi.PolicyResponse, error) {
	policyByte, err := ioutil.ReadAll(policyContent)

	policyContent = bytes.NewReader(policyByte)
	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePut, policyBranch, policyContent)

	if err != nil {
		err = fmt.Errorf("Failed to replace policy. %s", err)
	}

	// If policy load was successful store the newly replaces policy to the policy variable within the policy branch
	if err == nil && ignorePolicyVariable == false {
		policyContent = bytes.NewReader(policyByte)
		err = policyUpdatePolicyVariable(client, policyBranch, policyContent, false)
		if err != nil {
			return nil, err
		}
	}
	return policyResponse, err
}

func policyRollback(client *conjurapi.Client, policyBranch string, version int) (*conjurapi.PolicyResponse, error) {
	policyVariableID := getPolicyVariableID(policyBranch)
	currentVersion := getCurrentSecretVersion(client, policyVariableID)
	actualVersion := currentVersion - version

	policyContent, err := GetSecretVersion(client, policyVariableID, actualVersion)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch policy variable to perform rollback. %s", err)
	}
	policy := bytes.NewReader(policyContent)

	policyResponse, err := policyReplace(client, policyBranch, policy, "", false)
	if err != nil {
		err = fmt.Errorf("Failed to replace policy when performing a rollback. %s", err)
	}

	return policyResponse, err
}

func policyController(client *conjurapi.Client) {
	policyAction := readMandatoryArg(1, "policyAction", "append", "replace", "rollback", "delete", "append-no-save")
	policyBranch := readMandatoryArg(2, "policyBranch", "any valid policy id")

	var err error
	var policyResponse *conjurapi.PolicyResponse

	// rollback is a unique policy loading use case since we do not provide a policy file but a policyBranch name
	// if rollback is successful then exit with 0
	if policyAction == "rollback" {
		policyResponse, err = policyRollback(client, policyBranch, 1)
		if err != nil {
			writeStdErrAndExit(err)
		}
		os.Exit(0)
	}

	// get content of policy file being loaded
	fileName := readMandatoryArg(3, "policyFileName", "any valid file path")
	policyContent, err := getIoReader(fileName)
	if err != nil {
		writeStdErrAndExit(err)
	}

	// Will want to support append, replace, delete
	switch policyAction {
	case "append":
		policyResponse, err = policyAppend(client, policyBranch, policyContent, fileName, false)
	case "append-no-save":
		policyResponse, err = policyAppend(client, policyBranch, policyContent, fileName, true)
	case "replace":
		policyResponse, err = policyReplace(client, policyBranch, policyContent, fileName, false)
	}

	// Loading policy failed
	if err != nil {
		writeStdErrAndExit(err)
	} else {
		os.Stdout.WriteString("Policy loaded\n")
		fmt.Printf("%s", policyResponse)
	}
}

// ######################################
// # init action
// ######################################

func initTemplates(client *conjurapi.Client) ([]string, error) {
	folder := readMandatoryArg(2, "templatesFolder", "any valid folder containing policy templates")

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
	templatePolicy := bytes.NewReader([]byte("- !policy \r\n  id: templates\r\n"))
	_, err = policyAppend(client, "root", templatePolicy, "", false)
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

			_, err := policyAppend(client, "templates", variablePolicy, "", false)
			if err != nil {
				return nil, fmt.Errorf("Failed to load variable policy for variable '%s'. %s", f.Name(), err)
			}

			content, err := readFile(folder + "/" + f.Name())
			if err != nil {
				return nil, fmt.Errorf("Failed to read variable content file '%s'. %s", f.Name(), err)
			}

			err = setSecret(client, "templates/"+f.Name(), content)
			if err != nil {
				return nil, fmt.Errorf("Failed to load variable content '%s'. %s", f.Name(), err)
			}

			loadedTemplateVariables = append(loadedTemplateVariables, "templates/"+f.Name())
		}
	}

	return loadedTemplateVariables, nil

}

func initController(client *conjurapi.Client) {
	initAction := readMandatoryArg(1, "initAction", "templates", "login")

	switch initAction {
	case "templates":
		initTemplates, err := initTemplates(client)
		if err != nil {
			writeStdErrAndExit(err)
		}
		fmt.Println(strings.Join(initTemplates, "\n"))
	}

}

// ######################################
// # new-namespace action
// ######################################

func newNamespace(client *conjurapi.Client) error {
	namespaceName := readMandatoryArg(1, "namespaceName", "Any valid namespace name that has not already been created")

	// make sure namespace does not exists
	resourceID := makeFullID(client, "policy", namespaceName)
	_, err := client.Resource(resourceID)
	if err == nil {
		return fmt.Errorf("Failed to create namespace '%s' because it already exists", namespaceName)
	}

	// get the new-namespace template
	templateName := "templates/new-namespace.yml"
	log.Debug("new namespace template name: " + templateName)
	templateContent, err := GetSecret(client, templateName)
	if err != nil {
		return fmt.Errorf("Failed to retrieve template '%s'", templateName)
	}

	// replace placeholder in the template
	policyContent := strings.ReplaceAll(string(templateContent), "{{ NAMESPACE }}", namespaceName)
	policyReader := bytes.NewReader([]byte(policyContent))

	// load new-namespace template for this specific namespace
	response, err := policyAppend(client, "root", policyReader, "", false)
	if err != nil {
		log.Error("new-namespace policy content:\n" + policyContent)
		return fmt.Errorf("Failed to load new-namespace policy from template '%s'", templateName)
	}

	fmt.Println(response)

	return nil
}

func newNamespaceController(client *conjurapi.Client) {
	err := newNamespace(client)
	if err != nil {
		writeStdErrAndExit(err)
	}
}

// ######################################
// # namespace action
// ######################################
func namespaceOpen(client *conjurapi.Client) error {
	namespaceName := readMandatoryArg(1, "namespaceName", "Any valid namespace")

	// make sure namespace exists
	resourceID := makeFullID(client, "policy", namespaceName)
	_, err := client.Resource(resourceID)
	if err != nil {
		return fmt.Errorf("Failed to open namespace '%s' because it does not exists or you do not have permissions", namespaceName)
	}

	// get users home directory
	usr, err := user.Current()
	if err != nil {
		return errors.New("Failed to find user's home directory")
	}
	homeDir := usr.HomeDir

	// write to ~/.conjur.namespace file to save namespace location
	namespaceFileName := fmt.Sprintf("%s/.conjur.namespace", homeDir)
	data := []byte(namespaceName)
	err = ioutil.WriteFile(namespaceFileName, data, 0400)
	if err != nil {
		return fmt.Errorf("Failed to write namespace file '%s'. %s", namespaceFileName, err)
	}

	return nil

}

func namespaceController(client *conjurapi.Client) {

}

// handleAction()
// We have actions which is the first argument e.g. (get, set, policy, ..)
// The controller should handle stdout, stderr and exit codes.
// not much logic should be in this function
// every action should have its own controller
func handleAction() {
	action := readMandatoryArg(0, "action", "get", "set", "list", "policy", "login", "init", "new-namespace", "namespace")

	client, err := login()

	switch action {
	case "get":
		getController(client)
	case "set":
		setController(client)
	case "list":
		list(client, nil)
	case "policy":
		policyController(client)
	case "init":
		initController(client)
	case "new-namespace":
		newNamespaceController(client)
	case "namespace":
		namespaceController(client)
	case "login":
		if err != nil {
			writeStdErrAndExit(err)
		} else {
			os.Stdout.WriteString("Successfully authenticated to conjur\n")
		}
	}
}

// $ cam action args...
// e.g
// $ cam list
// $ cam policy append root root-policy.yml
// $ cam policy rollback root
// $ cam get secret id/to/secret
// $ cam set secret id/to/secret "Hello world"
// $ cam

// New resources
// 1. secrets
// 2. namespaces
// 3. apps
// 4. safe
// 5. auths

func main() {
	var help = golf.BoolP('h', "help", false, "show help")
	var verbose = golf.BoolP('v', "verbose", false, "be verbose")

	golf.Parse()

	log.SetFormatter(&log.TextFormatter{DisableTimestamp: true, DisableLevelTruncation: true})
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	if *help {
		golf.Usage()
		os.Exit(0)
	}

	handleAction()
}
