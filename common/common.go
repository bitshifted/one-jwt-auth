package common

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
)

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
