// Ecca Authentication CA server
//
// Performs all client certificate signing duties.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main

// This file contains the data storage bits

import (
	"log"
	"os"
		
        "github.com/coopernurse/gorp"
        "database/sql"
        _ "github.com/mattn/go-sqlite3"
)


var dbmap *gorp.DbMap

func init() {
        db, err := sql.Open("sqlite3", "eccaCA.sqlite3")
        check(err)
        dbmap = &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	// set key to be unique. We can't allow multiple CN's anyway.
        dbmap.AddTableWithName(Client{}, "clients").SetKeys(false, "CN")
	dbmap.CreateTables() // if not exists
        dbmap.TraceOn("[gorp]", log.New(os.Stdout, "eccaCA:", log.Lmicroseconds)) 
}


func writeClient(client Client) {
	check(dbmap.Insert(&client))
}

func getClient(CN string) (*Client) {
	res, err := dbmap.Get(Client{}, CN)
        log.Printf("Client is %#v, err is %#v\n", res, err)
        check(err)
        if res == nil { return nil } //type  assert can't handle nil :-(
        return res.(*Client)
}

