package policy

import (
	"fmt"
	"os"

	"github.com/AndrewCopeland/cam/cmd/cam/help"
	"github.com/AndrewCopeland/cam/pkg/camapi"
	"github.com/AndrewCopeland/cam/pkg/helper"
	"github.com/AndrewCopeland/conjur-api-go/conjurapi"
)

func Controller(client *conjurapi.Client) {
	policyAction := helper.ReadMandatoryArg(1, "policyAction", help.Policy, "append", "replace", "rollback", "delete", "append-no-save")
	policyBranch := helper.ReadMandatoryArg(2, "policyBranch", help.Policy, "any valid policy id")

	var err error
	var policyResponse *conjurapi.PolicyResponse

	// rollback is a unique policy loading use case since we do not provide a policy file but a policyBranch name
	// if rollback is successful then exit with 0
	if policyAction == "rollback" {
		policyResponse, err = camapi.Rollback(client, policyBranch, 1)
		if err != nil {
			helper.WriteStdErrAndExit(err)
		}
		os.Exit(0)
	}

	// get content of policy file being loaded
	fileName := helper.ReadMandatoryArg(3, "policyFileName", help.Policy, "any valid file path")
	policyContent, err := os.Open(fileName)
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}

	// Will want to support append, replace, delete
	switch policyAction {
	case "append":
		policyResponse, err = camapi.Append(client, policyBranch, policyContent, fileName, false)
	case "append-no-save":
		policyResponse, err = camapi.Append(client, policyBranch, policyContent, fileName, true)
	case "replace":
		policyResponse, err = camapi.Replace(client, policyBranch, policyContent, fileName, false)
	}

	// Loading policy failed
	if err != nil {
		helper.WriteStdErrAndExit(err)
	} else {
		os.Stdout.WriteString("Policy loaded\n")
		fmt.Printf("%s\n", helper.JsonPrettyPrint(policyResponse))
	}
}
