package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cyberark/conjur-api-go/conjurapi"
	"github.com/cyberark/conjur-api-go/conjurapi/authn"
	"github.com/karrick/golf"
	log "github.com/sirupsen/logrus"
)

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
	fmt.Fprintf(os.Stderr, "%s", err)
	os.Exit(1)
}

func newResourceFilter(kind string, annotation string) *conjurapi.ResourceFilter {
	annotation = "csasa" + annotation + "csasa"
	resourceFilter := conjurapi.ResourceFilter{Kind: kind, Search: annotation}
	return &resourceFilter
}

func getIoReader(fileName string) (io.Reader, error) {
	file, err := os.Open(fileName)
	return file, err
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

// ######################################
// # login action
// ######################################
func login() (*conjurapi.Client, error) {
	config, err := conjurapi.LoadConfig()

	if err != nil {
		err = logErrorAndReturnError("Failed to load configuration file.", err)
		return nil, err
	}

	conjur, err := conjurapi.NewClientFromKey(config,
		authn.LoginPair{
			Login:  os.Getenv("CONJUR_AUTHN_LOGIN"),
			APIKey: os.Getenv("CONJUR_AUTHN_API_KEY"),
		},
	)

	if err != nil {
		err = logErrorAndReturnError("Failed to authenticate to conjur.", err)
		return nil, err
	}

	return conjur, err
}

// ######################################
// # get action
// ######################################
func GetSecret(client *conjurapi.Client, variableID string) ([]byte, error) {
	result, err := client.RetrieveSecret(variableID)
	return result, err
}

func getSecret(client *conjurapi.Client) ([]byte, error) {
	var secretID = os.Args[3]
	result, err := GetSecret(client, secretID)

	if err != nil {
		err = logErrorAndReturnError(fmt.Sprintf("Failed to retrieve secret '%s'.", secretID), err)
		return nil, err
	}

	return result, err
}

func getTemplate(client *conjurapi.Client) ([]byte, error) {
	result, err := getSecret(client)
	return result, err
}

func getTemplates(client *conjurapi.Client) {
	filter := newResourceFilter("variable", "template")
	list(client, filter)
}

// Get a resource within conjur
func getController(client *conjurapi.Client) {
	var resource = os.Args[2]
	var response []byte
	var err error

	switch resource {
	case "secret":
		response, err = getSecret(client)
	case "template":
		getTemplate(client)
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
		err = logErrorAndReturnError("Failed to list resources secret.", err)
		return "", err
	}

	for _, resource := range resources {
		fmt.Println(resource["id"])
	}

	return "", nil
}

// ######################################
// # policy action
// ######################################
func policyUpdatePolicyVariable(client *conjurapi.Client, policyBranch string, policyContent io.Reader) error {
	// create policy IDs
	policyVariableID := getPolicyVariableID(policyBranch)
	fullPolicyVariableID := getFullPolicyVariableID(client, policyBranch)

	// make sure policy variable actually exists
	_, err := client.Resource(fullPolicyVariableID)

	// policy variable does not exists lets create it
	if err != nil {
		// load the policy file
		policyVariablePolicy, err := getIoReader("policy-variable.yml")
		if err != nil {
			err = fmt.Errorf("Failed to read policy template file 'policy-variable.'  %s", err)
			return err
		}

		// create the policy variable resource
		_, err = policyAppend(client, policyBranch, policyVariablePolicy, true)
		if err != nil {
			err = fmt.Errorf("Failed to create policy variable. %s", err)
			return err
		}

		// init the variable
		err = setSecret(client, policyVariableID, []byte("blank"))
		if err != nil {
			err = fmt.Errorf("Failed to init policy variable.  %s", err)
			return err
		}
	}

	// Make sure we can read the policy content
	newPolicyContent, err := ioutil.ReadAll(policyContent)
	if err != nil {
		return err
	}

	// Get the current policy variable content
	currentPolicyContent, err := GetSecret(client, policyVariableID)
	currentPolicyContent = append(currentPolicyContent, newPolicyContent...)

	// set the policy to the policy variable
	err = setSecret(client, policyVariableID, currentPolicyContent)

	return err
}

func policyAppend(client *conjurapi.Client, policyBranch string, policyContent io.Reader, ignorePolicyVariable bool) (*conjurapi.PolicyResponse, error) {
	policyResponse, err := client.LoadPolicy(conjurapi.PolicyModePost, policyBranch, policyContent)

	// If policy load was successful store the newly appended policy to the policy variable within the policy branch
	if err == nil && ignorePolicyVariable == false {
		err = policyUpdatePolicyVariable(client, policyBranch, policyContent)
		if err != nil {
			return nil, err
		}
	}
	return policyResponse, err
}

func policyRollback(client *conjurapi.Client, policyBranch string, version int) (*conjurapi.PolicyResponse, error) {
	return nil, nil
}

func policyController(client *conjurapi.Client) (*conjurapi.PolicyResponse, error) {
	policyAction := readMandatoryArg(1, "policyAction", "append", "replace", "rollback", "delete", "append-no-save")
	policyBranch := readMandatoryArg(2, "policyBranch", "any valid policy id")

	var err error
	var policyResponse *conjurapi.PolicyResponse

	// rollback is a unique policy loading use case since we do not provide a policy file but a policyBranch name
	if policyAction == "rollback" {
		policyResponse, err = policyRollback(client, policyBranch, 1)
	}
	if err != nil {
		writeStdErrAndExit(err)
	}

	// get content of policy file being loaded
	fileName := readMandatoryArg(3, "policyFileName", "any valid file name")
	policyContent, err := getIoReader(fileName)
	if err != nil {
		return nil, err
	}

	// Will want to support append, replace, delete
	switch policyAction {
	case "append":
		policyResponse, err = policyAppend(client, policyBranch, policyContent, false)
	case "append-no-save":
		policyResponse, err = policyAppend(client, policyBranch, policyContent, true)
	}

	// Loading policy failed
	if err != nil {
		writeStdErrAndExit(err)
	}

	return policyResponse, err
}

// handleAction()
// We have actions which is the first argument e.g. (get, set, policy, ..)
// The controller should handle stdout, stderr and exit codes.
// not much logic should be in this method
func handleAction(action string) {
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
	var action = os.Args[1]

	golf.Parse()
	handleAction(action)

	if *help {
		golf.Usage()
		os.Exit(0)
	}

	log.SetFormatter(&log.TextFormatter{DisableTimestamp: true, DisableLevelTruncation: true})
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

}
