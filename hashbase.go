// File: hashbase.go
//
// Copyright (c) 2013 Charles Perkins
// 
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.


// hashbase is a client and server library for storing, querying, and making assertions about hashes
package hashbase

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)


// Sha224base64 performs a sha224 hash on a byte array and then perfroms a base64 encoding on the result.
func Sha224base64(item []byte) (string, []byte) {

	phash := sha256.New224()
	io.WriteString(phash, string(item))
	phashbytes := phash.Sum(nil)
	return base64.StdEncoding.EncodeToString(phashbytes), phashbytes
}

func Un64( hash64val string) ([]byte, error){
	return base64.StdEncoding.DecodeString(hash64val)
}

// Sign64 signs a byte array with a private key.
func Sign64(rsakey *rsa.PrivateKey, item []byte) (string, []byte) {

	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(item)
	digest := h.Sum(nil)
	signresult, _ := rsa.SignPKCS1v15(rand.Reader, rsakey, hashFunc, digest)
	return base64.StdEncoding.EncodeToString(signresult), signresult
}

// GetPKI retrieves 'rputn' RSA public and private key values from the users ~/.ssh diretory or
// instructs the user to generate rputn RSA public and private key files.
func GetPKI() (*rsa.PrivateKey, []byte, error) {

	rsa_file := fmt.Sprintf("%s/.ssh/rputn_rsa", os.Getenv("HOME"))
	rsapub_file := fmt.Sprintf("%s/.ssh/rputn_rsa.pub", os.Getenv("HOME"))

	_, err := os.Stat(rsa_file)
	if err == nil {
		_, err = os.Stat(rsapub_file)
	}
	if err != nil {
		return nil, nil, errors.New("Please generate a reputation public/private key pair, e.g.:\n#ssh-keygen -t rsa -C \"<username>@<hostname>\" -f ~/.ssh/rputn_dsa\n")
	}

	rputn_rsa, _ := ioutil.ReadFile(rsa_file)
	rputn_rsa_pub, _ := ioutil.ReadFile(rsapub_file)
	block, _ := pem.Decode(rputn_rsa)
	rsakey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return rsakey, rputn_rsa_pub, nil
}

