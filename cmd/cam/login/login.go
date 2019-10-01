package login

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/AndrewCopeland/cam/pkg/helper"

	"golang.org/x/crypto/ssh/terminal"
)

var netrcTemplate string = `machine {{ APPLIANCE_URL }}/authn
  login {{ USERNAME }}
  password {{ PASSWORD }}
`

func credentials() (string, string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter Username: ")
	username, _ := reader.ReadString('\n')

	fmt.Print("Enter Password: ")
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	password := string(bytePassword)
	fmt.Println()

	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func getUrlFromConjurRc(conjurrcFileName string) string {
	file, err := os.Open(conjurrcFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "appliance_url: ") {
			url := strings.SplitN(line, ": ", 2)[1]
			url = strings.Trim(strings.Trim(url, "\n"), "\r")
			return url
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return ""
}

func createNetRc(username string, password string) error {
	// creatr ~/.netrc pas
	homeDir, err := helper.GetHomeDirectory()
	if err != nil {
		return err
	}

	conjurrcFileName := fmt.Sprintf("%s/.conjurrc", homeDir)
	url := getUrlFromConjurRc(conjurrcFileName)
	if url == "" {
		return fmt.Errorf("Failed to get appliance url from '%s'. Run 'cam init' to set this file", conjurrcFileName)
	}

	// create the ~/.netrc file
	netrcFileName := fmt.Sprintf("%s/.netrc", homeDir)
	fmt.Print("Replace ~/.netrc file [y]: ")
	// prompt user
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	answer := strings.Replace(text, "\n", "", -1)
	if answer == "" || answer == "y" {
		// create the ~/.netrc file
		netrcContent := strings.Replace(netrcTemplate, "{{ USERNAME }}", username, 1)
		netrcContent = strings.Replace(netrcContent, "{{ PASSWORD }}", password, 1)
		netrcContent = strings.Replace(netrcContent, "{{ APPLIANCE_URL }}", url, 1)

		err = ioutil.WriteFile(netrcFileName, []byte(netrcContent), 0400)
		if err != nil {
			return fmt.Errorf("Failed to write file '%s'. %s", netrcFileName, err)
		}
	}

	return err
}

func login() error {
	username, password := credentials()
	err := createNetRc(username, password)
	if err != nil {
		return fmt.Errorf("Failed to create ~/.netrc. %s", err)
	}

	return nil
}

func Controller() {
	err := login()
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
