package main

import (
	"bufio"
	"bytes"
	_ "crypto/sha256"
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/bitshifted/one-jwt-auth/common"
	"github.com/bitshifted/one-jwt-auth/jwt"
)

type authentication struct {
	XMLName  xml.Name `xml:"AUTHN"`
	Username string   `xml:"USERNAME"`
	Password string   `xml:"PASSWORD"`
	Secret   string   `xml:"SECRET"`
}

func main() {
	common.InitLogger()
	common.Logger.Info("Running authentication")
	reader := bufio.NewReader(os.Stdin)
	text := readAuthcenticationData(*reader)
	common.Logger.Debug(text)

	var data authentication
	xml.Unmarshal([]byte(text), &data)

	valid := jwt.Validate(data.Secret)
	common.Logger.Info(fmt.Sprintf("Valid signature: %t", valid))
	if !valid {
		os.Exit(20)
	}
	// check if username from token matches one from input
	parts := strings.Split(data.Secret, ".")
	payloadJSON := common.ConvertToJSON(parts[1])
	username := payloadJSON["preferred_username"].(string)
	common.Logger.Debug("Username from JSON: " + username)
	if data.Username != username {
		common.Logger.Error("Usernames mismatch")
		os.Exit(10)
	}

	fmt.Println("jwt " + username + " secret")

}

func readAuthcenticationData(reader bufio.Reader) string {
	text, _ := reader.ReadString('\n')
	buf := bytes.Buffer{}
	// expect input to be in multiple lines
	for text != "\n" {
		common.Logger.Debug("STDIN: " + text)
		buf.WriteString(strings.TrimSpace(text))
		// if we got whole input, get out
		if strings.HasPrefix(text, "<AUTHN>") && strings.HasSuffix(strings.TrimSpace(text), "</AUTHN>") {
			common.Logger.Debug("Got whole input in one line, breaking out")
			break
		}
		text, _ = reader.ReadString('\n')
	}
	return strings.TrimSpace(buf.String())

}
