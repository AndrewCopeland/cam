package helper

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"strings"

	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
	"github.com/karrick/golf"
)

func PromptUser(message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message + " ")
	text, _ := reader.ReadString('\n')
	url := strings.Replace(text, "\n", "", -1)
	return url
}

func arrayContains(array []string, contain string) bool {
	for _, arg := range array {
		if arg == contain {
			return true
		}
	}
	return false
}

func JsonPrettyPrint(response *conjurapi.PolicyResponse) string {
	pprint, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(pprint)
}

func JsonPrettyPrintMembersResponse(response []conjurapi.MemberResponse) string {
	pprint, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(pprint)
}

func JsonPrettyPrintMap(response map[string]interface{}) string {
	pprint, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(pprint)
}

func JsonPrettyPrintMapArray(response []map[string]interface{}) string {
	pprint, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(pprint)
}

// Should I put all my structs in one file, I could not reference it from camapi without getting an error
type AppResponse struct {
	Namespace      string
	App            string
	Safes          []string
	Authenticators []string
	ApiKey         string
}

func JsonPrettyPrintAppResponse(response AppResponse) string {
	pprint, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return string(pprint)
}

// WriteStdErrAndExit write error to stderr and os.Exit(1)
func WriteStdErrAndExit(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(1)
}

// ReadMandatoryArg read arg, if it does not exist call WriteStdErrAndExit()
func ReadMandatoryArg(index int, name string, help string, validArguments ...string) string {
	argValue := golf.Arg(index)
	if argValue == "" {
		err := fmt.Errorf("Mandatory argument '%s' is required. Valid arguments are '%s'", name, strings.Join(validArguments, ", "))
		fmt.Println(help)
		WriteStdErrAndExit(err)
	}

	// if --help flag was used
	if argValue == "--help" {
		err := fmt.Errorf("Mandatory argument '%s' is required. Valid arguments are '%s'", name, strings.Join(validArguments, ", "))
		fmt.Println(help)
		WriteStdErrAndExit(err)
	}

	// If first valid arguments contiains a " " then it is just explaining what is valid here
	if !strings.Contains(validArguments[0], " ") {
		if !arrayContains(validArguments, argValue) {
			err := fmt.Errorf("Mandatory argument '%s' is required. Valid arguments are '%s'", name, strings.Join(validArguments, ", "))
			fmt.Println(help)
			WriteStdErrAndExit(err)
		}
	}

	return argValue
}

func NewResourceFilter(kind string, annotation string) *conjurapi.ResourceFilter {
	// sandwiching annotation with csasa making querying much easier
	annotation = "csasa" + annotation + "csasa"
	resourceFilter := conjurapi.ResourceFilter{Kind: kind, Search: annotation}
	return &resourceFilter
}

func GetPolicyVariableID(policyBranch string) string {
	// Create policy ID
	policyVariableID := "policy"
	if policyBranch != "root" {
		policyVariableID = policyBranch + "/" + policyVariableID
	}
	return policyVariableID

}

func GetFullPolicyVariableID(client *conjurapi.Client, policyBranch string) string {
	policyVariableID := GetPolicyVariableID(policyBranch)
	policyVariableID = MakeFullID(client, "variable", policyVariableID)
	return policyVariableID
}

func ReadFile(fileName string) ([]byte, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	value, err := ioutil.ReadAll(file)
	return value, err
}

func MakeFullID(client *conjurapi.Client, kind string, id string) string {
	tokens := strings.SplitN(id, ":", 3)
	switch len(tokens) {
	case 1:
		tokens = []string{client.GetConfig().Account, kind, tokens[0]}
	case 2:
		tokens = []string{client.GetConfig().Account, tokens[0], tokens[1]}
	}
	return strings.Join(tokens, ":")
}

func GetHomeDirectory() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("Failed to find user's home directory. %s", err)
	}
	return usr.HomeDir, err
}

func GetNamespaceLocation(namespaceName string) (string, error) {
	homeDir, err := GetHomeDirectory()
	return fmt.Sprintf("%s/.cam.namespace", homeDir), err
}

func WriteNamespaceLocation(namespaceName string) error {
	// get namespace file name in home directory
	namespaceFileName, err := GetNamespaceLocation(namespaceName)
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
