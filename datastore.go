// Ecca Authentication CA server
//
// Performs all client certificate signing duties.
//
// Copyright 2013, Guido Witmond <guido@witmond.nl>
// Licensed under AGPL v3 or later. See LICENSE

package main

// This file contains the data storage bits

import (
	//"log"
	//"os"
		
        "github.com/coopernurse/gorp"
        "database/sql"
        _ "github.com/mattn/go-sqlite3"
)

type Datastore struct {
	Storename   string
	dbmap *gorp.DbMap
}

func DatastoreOpen(storename string) (*Datastore) {
        db, err := sql.Open("sqlite3", storename)
        check(err)
 	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.SqliteDialect{}}
	// set key to be unique. We can't allow multiple CN's anyway.
	// false -> no autogenerate of key.
        dbmap.AddTableWithName(Client{}, "clients").SetKeys(false, "CN")
	dbmap.CreateTables() // if not exists
        // dbmap.TraceOn("[gorp]", log.New(os.Stdout, "eccaCA:", log.Lmicroseconds)) 
	return &Datastore{
		Storename: storename,
		dbmap: dbmap,
	}
}

func (ds *Datastore) writeClient(client Client) {
	check(ds.dbmap.Insert(&client))
}

func (ds *Datastore) getClient(CN string) (*Client) {
	res, err := ds.dbmap.Get(Client{}, CN)
        //log.Printf("Client is %#v, err is %#v\n", res, err)
        check(err)
        if res == nil { return nil } //type  assert can't handle nil :-(
        return res.(*Client)
}

