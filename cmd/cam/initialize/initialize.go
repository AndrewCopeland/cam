package initialize

import (
	"bufio"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/AndrewCopeland/cam/pkg/helper"
)

var conjurrcTemplate string = `---
account: {{ ACCOUNT }}
plugins: []
appliance_url: {{ APPLIANCE_URL }}
cert_file: "{{ CERT_FILE }}"
`

func getPem(url string) (string, error) {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	// trim https://
	url = strings.TrimLeft(url, "https://")
	// If no port is provide default to port 443
	if !strings.Contains(url, ":") {
		url = url + ":443"
	}

	conn, err := tls.Dial("tcp", url, conf)
	if err != nil {
		return "", fmt.Errorf("Failed to retrieve certificate from '%s'. %s", url, err)
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) != 2 {
		return "", fmt.Errorf("Invalid conjur url '%s'. Make sure hostname and port are correct", url)
	}
	pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: conn.ConnectionState().PeerCertificates[0].Raw}))
	secondPemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: conn.ConnectionState().PeerCertificates[1].Raw}))
	pemCert = pemCert + secondPemCert

	return pemCert, err
}

func createConjurCert(certFileName string, url string) error {
	// make sure we can get the certificate
	pemCert, err := getPem(url)
	if err != nil {
		return err
	}

	// replace the cert file
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(fmt.Sprintf("Replace certificate file '%s' [y]: ", certFileName))
	text, _ := reader.ReadString('\n')
	answer := strings.Replace(text, "\n", "", -1)
	// overwrite file
	if answer == "" || answer == "y" {
		err = ioutil.WriteFile(certFileName, []byte(pemCert), 0400)
		if err != nil {
			return fmt.Errorf("Failed to write file '%s'. %s", certFileName, err)
		}
	}

	return err

}

func createConjurRcFile(account string, url string, certFileName string, conjurrcFileName string) error {
	fmt.Print("Replace ~/.conjurrc file [y]: ")
	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	answer := strings.Replace(text, "\n", "", -1)

	// overwrite ~/.conjurrc file
	if answer == "" || answer == "y" {
		if !strings.HasPrefix(url, "https://") {
			url = "https://" + url
		}

		// create ~/.conjurrrc contents
		conjurrcContent := strings.Replace(conjurrcTemplate, "{{ ACCOUNT }}", account, 1)
		conjurrcContent = strings.Replace(conjurrcContent, "{{ APPLIANCE_URL }}", url, 1)
		conjurrcContent = strings.Replace(conjurrcContent, "{{ CERT_FILE }}", certFileName, 1)

		err = ioutil.WriteFile(conjurrcFileName, []byte(conjurrcContent), 0400)
		if err != nil {
			return fmt.Errorf("Failed to write file '%s'. %s", conjurrcFileName, err)
		}
	}

	return err
}

func createConjurRc(account string, url string) error {
	// make sure we can get home directory
	homeDir, err := helper.GetHomeDirectory()
	if err != nil {
		return err
	}

	// create the ~/conjur-<accountName>.pem
	certFileName := fmt.Sprintf("%s/conjur-%s.pem", homeDir, account)
	err = createConjurCert(certFileName, url)
	if err != nil {
		return err
	}

	// create the ~/.conjurrc file
	conjurrcFileName := fmt.Sprintf("%s/.conjurrc", homeDir)
	err = createConjurRcFile(account, url, certFileName, conjurrcFileName)

	return err
}

func initialize() error {
	url := helper.PromptUser("DAP URL:")
	account := helper.PromptUser("DAP account:")

	err := createConjurRc(account, url)
	return err
}

func Controller() {
	err := initialize()
	if err != nil {
		helper.WriteStdErrAndExit(err)
	}
}
