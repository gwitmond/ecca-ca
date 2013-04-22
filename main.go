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
	//"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rsa"
	"crypto/rand"
	"math/big"
	//"crypto/tls"
	"encoding/pem"
	"io/ioutil"
	"os"
	//"html/template"
	//"database/sql"
	"time"
	"github.com/gwenn/gosqlite"
	"strconv"
	"flag"
)

// The things to set before running.
var configDir = flag.String("config", "example-dir", "Directory where the certificates and sqlite database are found.") 
var fpcaName = flag.String("fcpa", "exampleFPCA", "Prefix of the FPCA certificate and key file names.")
var hostname = flag.String("hostname", "register-application.example.nl", "Hostname of the FPCA-registration site. Prefix of the ssl server certificate and key file names.")
var bindaddress = flag.String("bind", "[::]:443", "Address and port number where to bind the listening socket.") 

// The certificate and key to sign client certificates with
var caCert *Certificate
var caKey *rsa.PrivateKey


func main() {
	flag.Parse()
	var err error
	// Set the certificate and key to sign client certificates with (and load now to check existence and validity)
	caCert, err = loadCaCert(*configDir + "/" + *fpcaName +".cert.pem")
	check(err)
	caKey, err = loadKey(*configDir + "/" + *fpcaName + ".key.pem")
        check(err)
	
	//http.HandleFunc("/", homePage)
	http.HandleFunc("/register-pubkey", registerPubkey)
	http.HandleFunc("/get-certificate", getCertificate)
	http.Handle("/static/", http.FileServer(http.Dir(".")))

	// initdb if necessary
	initdb()

	// Set  the server certificate to encrypt the connection with TLS
	ssl_certificate := *configDir + "/" + *hostname + ".cert.pem"
	ssl_cert_key   := *configDir + "/" + *hostname + ".key.pem"

	//bind and run
	log.Printf("About to start up. listening to %v", *bindaddress)	
	server6 := &http.Server{Addr: *bindaddress}
	check(server6.ListenAndServeTLS(ssl_certificate, ssl_cert_key))
}


func registerPubkey(w http.ResponseWriter, req *http.Request) {
	cn     := req.FormValue("cn")
	if cn == "" {
		http.Error(w, "There is no username! Please specify one.", 400)
		return
	}

	// Validate uniqueness of the username (Important requirement for Ecca)
	// BUG(gw): There is a slight race condition between the validation and generation ...
	nicks := getClients(cn)
	if len(nicks) > 0 {
		http.Error(w, fmt.Sprintf("Username: %v is already taken, please choose another.", cn), 403)
		return
	} 

	// validate the pubkey
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

	// Validation succeeded, sign, store and return certificate
	cert , err := signCert(cn, publicKey) // sign
	check(err)
	writeClient(client{CN: cn, certPEM: cert}) // store
	
	w.Header().Set("Content-Type", "text/plain") // return
	w.Header().Set("Content-Length", strconv.Itoa(len(cert)))
	w.WriteHeader(201) // set response code
	w.Write(cert)
	return
}

func signCert(cn string, publicKey interface{}) ([]byte, error) {
	// set up client structure template
	serial := randBigInt()
        // keyId := randBytes(20)
	//rand.Read(keyId)
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
		ExtKeyUsage:    []ExtKeyUsage{ExtKeyUsageClientAuth},
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
	nicks := getClients(nickname)
	switch len(nicks) {
	case 0: http.Error(w, "nickname not found", 404)
	case 1: w.Header().Set("Content-Type", "text/plain")
		w.Write(nicks[0].certPEM)
	default: log.Printf("ERROR: unexpected multiple certificates for %v. Got %#v\n", nickname, nicks)
	 	http.Error(w, "unexpected multiple certificates for nickname", 500)
	}
}

//////////////////////////////////////////////////////////////////
// Database

var dbFile = "eccaCA.db"
var db *sqlite.Conn

func initdb() {
	var err error
	db, err = sqlite.Open(*configDir + "/" + dbFile)
	check(err)	
	
	err = db.Exec("CREATE TABLE clients (cn TEXT, certPEM TEXT)")
	// check(err) // ignore
}

type client struct {
	CN      string
	certPEM []byte
}


func writeClient(client client) {
	st, err := db.Prepare("INSERT INTO clients (cn, certPEM) values (?, ?)")
	check(err)
	defer st.Finalize()

	count, err := st.Insert(client.CN, client.certPEM)
	check(err)
	log.Println("Inserted %d clients", count)
}

func getClients(nickname string) ([]client) {
	query, err := db.Prepare("SELECT cn, certPEM FROM clients WHERE cn = ?")
	check(err)
	defer query.Finalize()
	
	var cl []client
	err = query.Select(func (stmt *sqlite.Stmt) (err error) {
		var c client
		err = stmt.Scan(&c.CN, &c.certPEM)
		if err != nil { return }
		cl = append(cl, c)
		return
	}, nickname)
	check(err)
	return cl
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

// read certificate file or panic
// func readCert(certFile string) (*x509.CertPool) {
// 	pool := x509.NewCertPool()
//
// 	certPEMBlock, err := ioutil.ReadFile(certFile)
// 	if err != nil {
// 		panic("Cannot read certificate file " + certFile)
// 	}
// 	ok := pool.AppendCertsFromPEM(certPEMBlock)
// 	if !ok  {
// 		panic("Cannot parse certificate file " + certFile)
// 	}
// 	return pool
// }

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


