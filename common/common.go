package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/sirupsen/logrus"
)

var Logger = logrus.New()

// ConvertToJSON converts base64 encoded string into JSON
func ConvertToJSON(encodedData string) map[string]interface{} {
	data, err := base64.RawURLEncoding.DecodeString(encodedData)
	if err != nil {
		log.Fatal("Failed to decode JWT data")
	}
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&result); err != nil {
		log.Fatal("Failed to decode JSON")
	}
	return result
}

func InitLogger() {
	var file, err = os.OpenFile("/tmp/one-jwt-auth.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Could Not Open Log File : " + err.Error())
	}
	Logger.SetOutput(file)

	Logger.SetFormatter(&logrus.TextFormatter{})
}
