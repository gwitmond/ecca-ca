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
        "crypto/rsa"
        //"crypto/x509"
        //"crypto/x509/pkix"
        // "bytes"
        "encoding/pem"
        //"math/big"
        CryptoRand "crypto/rand"
        MathRand   "math/rand"
        "time"
        //"log"
	//"errors"
        //"github.com/gwitmond/eccentric-authentication" // package eccentric
        "github.com/gwitmond/eccentric-authentication/fpca" // package eccentric/fpca
        	// to make all those keys, certificates and DNSSEC records.
	"github.com/gwitmond/eccentric-authentication/utils/camaker" // CA maker tools.
)

var config = quick.Config {
        MaxCount: 10,
        Rand: MathRand.New(MathRand.NewSource(time.Now().UnixNano())),
}


// sets up fpca in main.go
var  rootCaCert, rootCaKey, _ = camaker.GenerateCA("The Root CA", "RootCA", 512)
var fpcaCert, fpcaKey, _ = camaker.GenerateFPCA("The FPCA Org", "FPCA", rootCaCert, rootCaKey, 512)

// Test Tree setup. 
func TestTreeSetup(t *testing.T) {
	// FPCA must be signed by RootCA.
	err := fpcaCert.CheckSignatureFrom(rootCaCert)
	if err != nil {
		t.Error(err)
	}
}

// Test to check correct signature generation
func TestClientCert(t *testing.T) {
	// sets ds in main.go
	ds = DatastoreOpen(":memory:")
	ca = &fpca.FPCA{
		Namespace: "test",
		CaCert:        fpcaCert,
		CaPrivKey:  fpcaKey,
	}

	testf := func(cn string) bool {
		// cn = srand(len(cn))
		privkey, err := rsa.GenerateKey(CryptoRand.Reader, 384)
		check(err)

		// To test
		certPem , err := signCert(cn, &privkey.PublicKey) // sign
		check(err)
		
		// Validate
		block, _ := pem.Decode(certPem)
		cert, err := parseX509Cert(block.Bytes)
		check(err)

		// Client Cert must be signed by FPCA.
		err = cert.CheckSignatureFrom(fpcaCert)
		if err != nil {
			t.Error("Wrong signer: ", err)
		}
		
		// Client Cert must no be signed by rootCaCert.
		err = cert.CheckSignatureFrom(rootCaCert)
		if err == nil {
			t.Error("Client cert signed by Root ")
		}
		
		// Test Common Name
		if cert.Subject.CommonName != cn {
			t.Error("Certificate does not have correct CommonName")
		}
			
		// // store
		// ds.writeClient(c)
		
		// // retrieve
		// res := ds.getClient(c.CN)

		return true // it bombed out before if there were errors
	}

	err := quick.Check(testf, &config)
	if err != nil {
		t.Error(err)
	}
}


/// test utils that get copied everywhere

var alpha = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
// generates a random string of expected size
func srand(size int) string {
    buf := make([]byte, size)
    for i := 0; i < size; i++ {
        buf[i] = alpha[MathRand.Intn(len(alpha))]
    }
    return string(buf)
}

