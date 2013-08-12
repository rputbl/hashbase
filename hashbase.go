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

// Un64 decodes a base-64 encoded hash string and returns a byte array or an error.
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

// HashPersister provides access to hash storage
type HashPersister interface {
   Assert( string, string, string ) error
   Query( string ) (string, error)
   Load( io.Reader ) error
   Unload(io.Writer ) error
   Init() bool
}

// WatchableHashPersister adds watching for assertions on hashes in a HashPersister
type WatchableHashPersister interface {
   HashPersister 
   Watch() int
   Unwatch() int
}


// LocalFileHashes keeps hash information in a local file
type LocalFileHashes struct {
   length, width int
}

func (lfh LocalFileHashes) Assert() int {
   return 1
}

func (lfh LocalFileHashes) Query() int {
   return 1
}

func (lfh LocalFileHashes) Load( f io.Reader ) error {
   return nil
}

func (lfh LocalFileHashes) Unload(f io.Writer ) error {
   return nil
}


// RawDiskHashes keeps hash information in raw disk partitions
type RawDiskHashes struct {
   length, width int
}

// RemotelyStoredHashes uses remote HashPersisters to satisfy requests
type RemotelyStoredHashes struct {
   length, width int
}

// MigratingStoreHashes moves hashes between tiers of HashPersisters
type MigratingStoreHashes struct {
   length, width int
}

// LoadBalancingHashes divides hashes between HashPersisters
type LoadBalancingHashes struct {
   length, width int
}

// FaultTolerantHashes replicates hashes to HashPersisters
type FaultTolerantHashes struct {
   length, width int
}



//type Rectangle struct {
//   length, width int
//}

//func (r Rectangle) Area() int {
//   return r.length * r.width
//}

//type Square struct {
//   side int
//}

//func (sq Square) Area() int {
//   return sq.side * sq.side
//}

//func main() {
//   r := Rectangle{length:5, width:3}
//   q := Square{side:5}
//   shapesArr := [...]HashPersister{r, q}
//
//   fmt.Println("Looping through shapes for area ...")
//   for n, _ := range shapesArr {
//       fmt.Println("Shape details: ", shapesArr[n])
//       fmt.Println("Area of this shape is: ", shapesArr[n].Area())
//   }
//}

