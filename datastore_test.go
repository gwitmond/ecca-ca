// Ecca Authentication CA server
//
// Performs all client certificate signing duties.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

// Testing code

package main // eccaproxy

import (
        "testing"
        "testing/quick"
        "bytes"
        MathRand   "math/rand"
        "time"
)

// simple test to check correct working of datastore routines
func TestMemoryDB(t *testing.T) {
	// sets ds in main.go
	ds = DatastoreOpen(":memory:")

	testStoreRetrieve := func(c Client) bool {
		// store
		ds.writeClient(c)
		
		// retrieve
		res := ds.getClient(c.CN)

		return bytes.Equal(res.CertPEM, c.CertPEM)
	}
	err := quick.Check(testStoreRetrieve, 
		&quick.Config{
			MaxCount: 10,
			Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
		})
	if err != nil {
		t.Error(err)
	}
}



