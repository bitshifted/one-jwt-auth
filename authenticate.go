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
	fmt.Print("Running auth")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	fmt.Println(text)

	var data authentication
	xml.Unmarshal([]byte(text), &data)
	fmt.Println(data.Secret)

	valid := jwt.Validate(data.Secret)
	fmt.Println(fmt.Sprintf("Valid signature: %t", valid))
	// check if username from token matches one from input
	parts := strings.Split(data.Secret, ".")
	payloadJSON := common.ConvertToJSON(parts[1])
	username := payloadJSON["preferred_username"].(string)
	fmt.Println("Username from JSON: " + username)
	if data.Username != username {
		fmt.Println("Usernames mismtach")
	}

	fmt.Println("jwt " + username + " secret")

}
