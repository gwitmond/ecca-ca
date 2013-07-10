// Ecca Authentication CA server
//
// Performs all client certificate signing duties.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE.

package main

import (
	"log"
	"fmt"
	"errors"
	"net/http"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/rand"
	"math/big"
	"encoding/pem"
	"io/ioutil"
	"os"
	"time"
	"strconv"
	"flag"
	"strings"
)

// The things to set before running.
var configDir = flag.String("config", "example-dir", "Directory where the certificates and sqlite database are found.") 
var fpcaName = flag.String("fcpa", "exampleFPCA", "Prefix of the FPCA certificate and key file names.")
var hostname = flag.String("hostname", "register-application.example.nl", "Hostname of the FPCA-registration site. Prefix of the ssl server certificate and key file names.")
var bindaddress = flag.String("bind", "[::]:443", "Address and port number where to bind the listening socket.") 
var namespace = flag.String("namespace", "", "Name space that we are signing. I.E. <cn>@@example.com. Specifiy the part after the @@.")

// The certificate and key to sign client certificates with. 
var caCert *Certificate
var caKey *rsa.PrivateKey


func main() {
	flag.Parse()
	var err error
	
	log.Printf("Parsed parameters: namespace is: %#v\n", *namespace)
	// validate NameSpace.
	if *namespace == "" {
		panic(errors.New("No namespace specified. We need one, otherwise we can't sign certificates!"))
	}
	// TODO: validate namespace with FPCA root certificate to prevent mistakes. Panic if wrong.

	// Set the certificate and key to sign client certificates with (and load now to check existence and validity)
	caCert, err = loadCaCert(*configDir + "/" + *fpcaName +".cert.pem")
	check(err)
	caKey, err = loadKey(*configDir + "/" + *fpcaName + ".key.pem")
        check(err)
	
	//http.HandleFunc("/", homePage)
	http.HandleFunc("/register-pubkey", registerPubkey)
	http.HandleFunc("/get-certificate", getCertificate)
	http.Handle("/static/", http.FileServer(http.Dir(".")))

	// Set  the server certificate to encrypt the connection with TLS
	ssl_certificate := *configDir + "/" + *hostname + ".cert.pem"
	ssl_cert_key   := *configDir + "/" + *hostname + ".key.pem"

	//bind and run
	log.Printf("About to start up. listening to %v", *bindaddress)	
	server6 := &http.Server{Addr: *bindaddress}
	check(server6.ListenAndServeTLS(ssl_certificate, ssl_cert_key))
}


func registerPubkey(w http.ResponseWriter, req *http.Request) {
	cn  := req.FormValue("cn")
	fmt.Printf("cn is %s\n", cn)

	if cn == "" {
		http.Error(w, "There is no username! Please specify one.", 400)
		return
	}

	if  strings.Contains(cn, "@") {
		http.Error(w, "We could not recognise your name: it should be without @-sign.", 400)
		return
	}

	// TODO: sanitise input, ie, strip leading and trailing white space, collapse all embedded whitespace into a single one.
	// Perhaps blacklist certain 'sensitive' names such as root/administrator...
	// Names must be unique.
	// They must alse be recognisably different for humans.  <cn> == < cn> == <cn    >
	
	// This will be the full identity for the user. This is what we sign.
	cn = fmt.Sprintf("%s@@%s", cn, *namespace)
	
	// Validate uniqueness of the CN (Important requirement for Ecca)
	// BUG(gw): There is a slight race condition between the validation and generation ...
	nick := getClient(cn)
	if nick != nil {
		http.Error(w, fmt.Sprintf("Username: %v is already taken, please choose another.", cn), 403)
		return
	} 

	// Validate that we have a pubkey
	pubkey := req.FormValue("pubkey")
	if pubkey == "" {
		http.Error(w, "There is no Public Key! Please specify one.", 400)
		return
	}
	
	// Validate that we have a correct public key
	block, _ := pem.Decode([]byte(pubkey))
	// TODO: validate block.Type == "PUBLIC KEY"
	publicKey, err := ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		http.Error(w, fmt.Sprintf("Public key does not parse. Error is: %#v\n:\n%#v\n", pubkey), 400)
		return
	}

	// Validation succeeded, sign, store certificate in db and hand it to the requestor
	cert , err := signCert(cn, publicKey) // sign
	check(err)
	writeClient(Client{CN: cn, CertPEM: cert}) // store
	
	w.Header().Set("Content-Type", "text/plain") // return
	w.Header().Set("Content-Length", strconv.Itoa(len(cert)))
	w.WriteHeader(201) // set response code to 'Created'
	w.Write(cert)
	return
}

func signCert(cn string, publicKey interface{}) ([]byte, error) {
	// set up client structure template
	serial := randBigInt()
	template := Certificate{
                Subject: pkix.Name{
                        CommonName: cn,
		},
		// add restrictions: CA-false, authenticate, sign, encode, decode, no server!
                SerialNumber:   serial,
                //SubjectKeyId:   keyId,
                AuthorityKeyId: caCert.AuthorityKeyId,
                NotBefore:      time.Now().Add(-5 * time.Minute).UTC(),
                NotAfter:       time.Now().AddDate(10, 0, 0).UTC(),
		IsCA:           false,
		KeyUsage:       KeyUsageDigitalSignature + KeyUsageContentCommitment + KeyUsageDataEncipherment + KeyUsageKeyAgreement,
		ExtKeyUsage:    []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageEmailProtection },
        }

	derBytes, err := CreateClientCertificate(rand.Reader, &template, caCert, publicKey, caKey)
	if err != nil {
		return nil, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return cert, nil
}

func getCertificate(w http.ResponseWriter, req *http.Request) {
	nickname := req.FormValue("nickname")

	if nickname == "" {
		http.Error(w, "There is no username! Please specify one.", 400)
		return
	}
	
	// Check if nickname already exists
	nick := getClient(nickname)
	switch nick {
	case nil: http.Error(w, "nickname not found", 404)
	default: 
		w.Header().Set("Content-Type", "text/plain")
		w.Write(nick.CertPEM)
	}
}


// Database types
type Client struct {
	CN      string
	CertPEM []byte
}


//////////////////////////////////////////////////////////////////
// UTILS

func loadCaCert(filename string) (*Certificate, error) {
        f, err := os.Open(filename)
        check(err)
        defer f.Close()
        der, err := ioutil.ReadAll(f)
        check(err)
        block, _ := pem.Decode(der)
        certs, err := ParseCertificates(block.Bytes)
        check(err)
        if len(certs) != 1 {
                return nil, errors.New("Cannot parse CA certificate file")
        }
        return certs[0], nil
}

func loadKey(filename string) (*rsa.PrivateKey, error) {
        f, err := os.Open(filename)
        check(err)
        defer f.Close()
        der, err := ioutil.ReadAll(f)
        check(err)
        block, _ := pem.Decode(der)
        return ParsePKCS1PrivateKey(block.Bytes)
}

var (
        maxInt64 int64 = 0x7FFFFFFFFFFFFFFF
        maxBig64       = big.NewInt(maxInt64)
)

func randBigInt() (value *big.Int) {
        value, _ = rand.Int(rand.Reader, maxBig64)
        return
}

func randBytes(count int) (bytes []byte) {
        bytes = make([]byte, count)
        rand.Read(bytes)
        return
}
	
func check(err error) {
	if err != nil {
		panic(err)
	}
}


