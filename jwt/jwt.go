package jwt

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/bitshifted/one-jwt-auth/common"
	"github.com/bitshifted/one-jwt-auth/jwks"
)

// Validate validates JWT token
func Validate(encodedToken string) bool {
	// split encoded token
	parts := strings.Split(encodedToken, ".")
	jwtHeader := common.ConvertToJSON(parts[0])
	keyID := jwtHeader["kid"].(string)
	common.Logger.Info("Key ID: " + keyID)

	jwtPayload := common.ConvertToJSON(parts[1])
	// check if token is expired
	tokenHasExpired := isTokenExpired(jwtPayload)
	if tokenHasExpired {
		common.Logger.Error("Token has expired")
		return false
	}
	// verify signature
	key, err := jwks.GetSigningKey(keyID, parts[1])
	if err != nil {
		common.Logger.Error(fmt.Sprintf("Could not get signing key: %s", err.Error()))
		return false
	}
	// based on https://medium.com/@software_factotum/validating-rsa-signature-for-a-jws-10229fb46bbf
	message := []byte(strings.Join(parts[0:2], "."))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
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
		common.Logger.Error("Invalid signature")
		return false
	}

	return true
}

func isTokenExpired(payload map[string]interface{}) bool {
	expirationTimeUnix := int64(payload["exp"].(float64))
	expirationTime := time.Unix(expirationTimeUnix, 0)
	currentTime := time.Now()
	return expirationTime.Before(currentTime)
}
