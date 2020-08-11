package jwks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bitshifted/one-jwt-auth/common"
)

const keyCachePath = "/tmp/jwt-auth/%s"

//JWKS collection of JWK keys
type JWKS struct {
	Keys []JWK
}

// JWK key
type JWK struct {
	Alg string
	Kty string
	X5c []string
	N   string
	E   string
	Kid string
	X5t string
}

// GetSigningKey returns JWT signing key
func GetSigningKey(keyID string, jwtPayloadEncoded string) (JWK, error) {
	var key JWK
	var err error = nil
	if checkIfKeyIsCached(keyID) {
		key, err = getKeyFromFile(fmt.Sprintf(keyCachePath, keyID), keyID)
	} else {
		oidcConfigURL := getOIDCConfigURL(jwtPayloadEncoded)
		common.Logger.Debug("OIDC URL: " + oidcConfigURL)
		jwksURL := getJWKSUrl(oidcConfigURL)
		common.Logger.Debug("JWKS URL: " + jwksURL)
		cachedKeyFile := downloadJwksJSON(jwksURL)
		common.Logger.Debug("Cached key file: " + cachedKeyFile)
		key, err = getKeyFromFile(cachedKeyFile, keyID)
	}
	return key, err
}

func checkIfKeyIsCached(keyID string) bool {
	filePath := fmt.Sprintf(keyCachePath, keyID)
	_, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		common.Logger.Info("Cached key file not found")
		return false
	}
	return true
}

func getKeyFromFile(keyFilePath string, keyID string) (JWK, error) {

	jwksFile, err := os.Open(keyFilePath)
	if err != nil {
		common.Logger.Error("Failed to open JWKS file: " + err.Error())
		return JWK{}, err
	}
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS
	if err := dec.Decode(&jwks); err != nil {
		common.Logger.Error("Could not decode JWKS file: " + err.Error())
		return JWK{}, err
	}
	// loop through keys and find one with supplied ID
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == keyID {
			return jwks.Keys[i], nil
		}
	}
	return JWK{}, errors.New("Key not found")
}

func getOIDCConfigURL(encodedPayload string) string {
	jwtPayload := common.ConvertToJSON(encodedPayload)
	issuer := jwtPayload["iss"].(string)
	return issuer + "/.well-known/openid-configuration"
}

func getJWKSUrl(oidcConfigURL string) string {

	body, readErr := doDownload(oidcConfigURL)
	if readErr != nil {
		common.Logger.Error(readErr)
	}
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&result); err != nil {
		fmt.Println("Could not decode OIDC config")
	}
	return result["jwks_uri"].(string)
}

func downloadJwksJSON(url string) string {

	body, readErr := doDownload(url)
	if readErr != nil {
		common.Logger.Error(readErr)
	}
	var keys JWKS
	jsonErr := json.Unmarshal(body, &keys)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}
	fmt.Println(keys.Keys[0].Kid)
	// cache to file
	cacheDirPath := filepath.Join("/", "tmp", "jwt-auth")
	os.MkdirAll(cacheDirPath, os.ModePerm)
	cacheFilePath := filepath.Join("/", "tmp", "jwt-auth", keys.Keys[0].Kid)

	out, err := os.Create(cacheFilePath)
	if err != nil {
		log.Fatal("Failed to open cache file")
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, bytes.NewReader(body))
	if err != nil {
		log.Fatal("Failed to write cache file")
	}
	return cacheFilePath

}

func doDownload(url string) ([]byte, error) {
	httpClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		common.Logger.Error(err)
		return nil, err
	}
	res, getErr := httpClient.Do(req)
	if getErr != nil {
		common.Logger.Error(getErr)
		return nil, getErr
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		common.Logger.Error(readErr)
		return nil, readErr
	}
	return body, nil
}
