package main

import (
	"bufio"
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
	text, _ := reader.ReadString('\n')
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
