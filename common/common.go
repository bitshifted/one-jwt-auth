package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
)

var Logger = logrus.New()

// ConvertToJSON converts base64 encoded string into JSON
func ConvertToJSON(encodedData string) map[string]interface{} {
	data, err := base64.RawURLEncoding.DecodeString(encodedData)
	var result map[string]interface{}
	if err != nil {
		Logger.Error("Failed to decode encoded data: " + err.Error())
		return result
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&result); err != nil {
		Logger.Error("Failed to decode JSON: " + err.Error())
	}
	return result
}

func InitLogger() {
	var file, err = os.OpenFile("/tmp/one-jwt-auth.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("Could Not Open Log File : " + err.Error())
	}
	Logger.SetOutput(file)
	Logger.SetLevel(logrus.DebugLevel)
	Logger.SetFormatter(&logrus.TextFormatter{})
}
