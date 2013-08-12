// File: localmaphashes.go
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


package hashbase

import (
	"errors"
	"io"
	_ "crypto/sha1"
)



// LocalMapHashes keeps hash information in local memory
type LocalMapHashes struct {
  m map[string]string
}

func (lmh *LocalMapHashes) Init() bool {
	lmh.m = make(map[string]string)
	return true
}

func (lmh *LocalMapHashes) Assert(fh64val,ph64val,assertstr string) error {
	if ph64val == "INTRODUCING"{
		lmh.m[fh64val] = assertstr
	}else{
		_, exists := lmh.m[ph64val]
		if !exists {
			return errors.New("DENIEDASSERT-UNKNOWN-ASSERTER")
		}

		lmh.m[fh64val] = assertstr
	}

        return nil
}

func (lmh *LocalMapHashes) Query( hash64val string ) (string,error) {

	assert, exists := lmh.m[hash64val]
	if exists{
		return assert, nil
	}
	return "",errors.New("QUERY-UNKNOWN-HASH")
}

func (lmh *LocalMapHashes) Load( f io.Reader ) error {
   return nil
}

func (lmh *LocalMapHashes) Unload(f io.Writer ) error {
   return nil
}


