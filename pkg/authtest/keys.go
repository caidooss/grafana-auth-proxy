package authtest

import (
	"crypto/rsa"
	"io/ioutil"
	"path"
	"runtime"

	"github.com/dgrijalva/jwt-go"
)

var testdataDir string

func init() {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir = path.Join(path.Dir(filename), "testdata")
}

func LoadPrivateKey() *rsa.PrivateKey {
	return loadPrivateKeyFromDisk(path.Join(testdataDir, "sample_key"))
}

func LoadAttackerPrivateKey() *rsa.PrivateKey {
	return loadPrivateKeyFromDisk(path.Join(testdataDir, "attacker_key"))
}

func LoadPublicKey() *rsa.PublicKey {
	return loadPublicKeyFromDisk(path.Join(testdataDir, "sample_key.pub"))
}

func loadPrivateKeyFromDisk(location string) *rsa.PrivateKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	key, e := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}

	return key
}

func loadPublicKeyFromDisk(location string) *rsa.PublicKey {
	keyData, e := ioutil.ReadFile(location)
	if e != nil {
		panic(e.Error())
	}

	key, e := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if e != nil {
		panic(e.Error())
	}

	return key
}
