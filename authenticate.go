package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type authentication struct {
	XMLName  xml.Name `xml:"AUTHN"`
	Username string   `xml:"USERNAME"`
	Password string   `xml:"PASSWORD"`
	Secret   string   `xml:"SECRET"`
}

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Alg string
	Kty string
	X5c []string
	N   string
	E   string
	Kid string
	X5t string
}

func main() {
	fmt.Print("Running auth")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	fmt.Println(text)

	var data authentication
	xml.Unmarshal([]byte(text), &data)
	fmt.Println(data.Secret)

	parts := strings.Split(data.Secret, ".")
	message := []byte(strings.Join(parts[0:2], "."))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		fmt.Println("Error!")
	}
	keyID := getKeyID(parts[0])
	fmt.Println("Key ID: " + keyID)
	oidcConfigURL := getOIDCConfigURL(parts[1])
	fmt.Println("OIDC config: " + oidcConfigURL)

	cachedJwks := downloadJwksJSON(getJWKSUrl(oidcConfigURL))

	// based on https://medium.com/@software_factotum/validating-rsa-signature-for-a-jws-10229fb46bbf
	key := getKeyFromFile(cachedJwks).Keys[0]
	n, _ := base64.RawURLEncoding.DecodeString(key.N)
	e, _ := base64.RawURLEncoding.DecodeString(key.E)
	z := new(big.Int)
	z.SetBytes(n)
	//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
	//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(e)
	exponent := binary.BigEndian.Uint32(buffer.Bytes())
	publicKey := &rsa.PublicKey{N: z, E: int(exponent)}

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed.
	hasher := crypto.SHA256.New()
	hasher.Write(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hasher.Sum(nil), signature)
	if err != nil {
		fmt.Println("Invalid signature")
	} else {
		fmt.Println("Signature valid")
	}
}

func getKeyFromFile(keyFilePath string) JWKS {

	jwksFile, err := os.Open(keyFilePath)
	if err != nil {
		fmt.Println("Failed to open JWKS file")
	}
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS
	if err := dec.Decode(&jwks); err != nil {
		fmt.Println("Could not decode JWKS")
	}
	return jwks
}

func getJWKSUrl(oidcConfigURL string) string {
	httpClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, oidcConfigURL, nil)
	if err != nil {
		log.Fatal(err)
	}
	res, getErr := httpClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&result); err != nil {
		fmt.Println("Could not decode OIDC config")
	}
	return result["jwks_uri"].(string)
}

func downloadJwksJSON(url string) string {
	httpClient := http.Client{
		Timeout: time.Second * 2, // Timeout after 2 seconds
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}
	res, getErr := httpClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}
	var jwks JWKS
	jsonErr := json.Unmarshal(body, &jwks)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}
	fmt.Println(jwks.Keys[0].Kid)
	// cache to file
	cacheDirPath := filepath.Join("/", "tmp", "jwt-auth")
	os.MkdirAll(cacheDirPath, os.ModePerm)
	cacheFilePath := filepath.Join("/", "tmp", "jwt-auth", jwks.Keys[0].Kid)

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

func convertToJSON(encodedData string) map[string]interface{} {
	data, err := base64.RawURLEncoding.DecodeString(encodedData)
	if err != nil {
		log.Fatal("Failed to decode JWT data")
	}
	var result map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&result); err != nil {
		fmt.Println("Could not decode JSON data")
	}
	return result
}

func getKeyID(encodedHeader string) string {
	return convertToJSON(encodedHeader)["kid"].(string)
}

func getOIDCConfigURL(encodedPayload string) string {
	jwtPayload := convertToJSON(encodedPayload)
	issuer := jwtPayload["iss"].(string)
	return issuer + "/.well-known/openid-configuration"
}
