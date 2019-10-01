package cyberarkapi

// would be cool to support all cyberark methods at somepoint and create a client for cyberark. this will do for now

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/AndrewCopeland/cam/pkg/httpJson"
)

func header(token string) http.Header {
	header := make(http.Header)
	header.Add("Authorization", token)
	return header
}

// Authenticate to cyberark API
func Authenticate(hostname string, username string, password string) (token string, err error) {
	url := fmt.Sprintf("https://%s/PasswordVault/API/auth/Cyberark/Logon", hostname)
	body := fmt.Sprintf("{\"username\": \"%s\", \"password\":\"%s\"}", username, password)
	response, err := httpJson.SendRequestRaw(url, "POST", nil, body)
	if err != nil {
		return "", fmt.Errorf("Failed to authenticate to the cyberark api. %s", err)
	}
	return strings.Trim(string(response), "\""), err
}

// ListApplications from cyberark
func ListApplications(hostname string, token string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://%s/PasswordVault/WebServices/PIMServices.svc/Applications/", hostname)
	header := header(token)
	response, err := httpJson.Get(url, header)
	return response, err
}

// ListApplicationAuthenticationMethods from cyberark
func ListApplicationAuthenticationMethods(hostname string, token string, appName string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://%s/PasswordVault/WebServices/PIMServices.svc/Applications/%s/Authentications", hostname, appName)
	header := header(token)
	response, err := httpJson.Get(url, header)
	return response, err
}

// ListSafes from cyberark user has access too
func ListSafes(hostname string, token string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://%s/PasswordVault/WebServices/PIMServices.svc/Safes", hostname)
	// fmt.Println(url)
	header := make(http.Header)
	header.Add("Authorization", token)
	response, err := httpJson.Get(url, header)
	return response, err
}

// ListSafeMembers List all members of a safe
func ListSafeMembers(hostname string, token string, safeName string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://%s/PasswordVault/WebServices/PIMServices.svc/Safes/%s/Members", hostname, safeName)
	// fmt.Println(url)
	header := make(http.Header)
	header.Add("Authorization", token)
	response, err := httpJson.Get(url, header)
	return response, err
}

// GetSafesUserIsMemberOf Iterate through all safes and see which safe username is member of
// This method performs ListSafes() and ListSafeMembers()
func GetSafesUserIsMemberOf(hostname string, token string, username string) ([]string, error) {
	// List safes
	response, err := ListSafes(hostname, token)
	if err != nil {
		return nil, fmt.Errorf("Failed to list cyberark safes %s", err)
	}

	safes := response["GetSafesResult"].([]interface{})
	var safesUserIsMemberOf []string

	// Iterate through safes get members and see if member of safe is 'username' provided
	for _, safe := range safes {
		safeInterface := safe.(map[string]interface{})
		safeName := safeInterface["SafeName"].(string)

		// now query each safe for this specific username
		response, err = ListSafeMembers(hostname, token, safeName)
		if err != nil {
			return nil, fmt.Errorf("Failed to list safe members for safe '%s'. %s", safeName, err)
		}

		members := response["members"].([]interface{})

		for _, member := range members {
			memberInterface := member.(map[string]interface{})
			safeMember := memberInterface["UserName"].(string)
			if safeMember == username {
				safesUserIsMemberOf = append(safesUserIsMemberOf, safeName)
			}
		}
	}
	return safesUserIsMemberOf, err
}
