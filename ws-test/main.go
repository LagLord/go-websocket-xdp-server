package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	_ "net/http/pprof"
)

func main() {
	log.SetFlags(0)

	err := run()
	if err != nil {
		log.Fatal(err)
	}
}

// run starts a http.Server for the passed in address
// with all requests handled by echoServer.
func run() error {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	InitGlobalStructs()
	
	for i,val:= range os.Args {
		fmt.Printf("%v : %v\n", i, val)
	}
	if len(os.Args) < 2 {
		return errors.New("please provide an address to listen on as the first argument")
	}

	l, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		return err
	}
	log.Printf("listening on ws://%v", l.Addr())

	s := &http.Server{
		Handler: echoServer{
			logf: log.Printf,
		},
		ReadTimeout:  time.Second * 10,
		WriteTimeout: time.Second * 10,
		IdleTimeout: 30,
		// Will require 4kb header padding for accept request to make spam costly 
		// Will also make this a limit for all messages for future ws requests

		// Payload for connecting should be between [4kb-5kb) while msgs should be between [20b-4kb)
		// Can then apply the above limit to filter/reject messages
		// Is pretty constraint but should work well for text based comms
		MaxHeaderBytes: 5000,

		
	}
	errc := make(chan error, 1)
	go func() {
		errc <- s.Serve(l)
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	select {
	case err := <-errc:
		log.Printf("failed to serve: %v", err)
	case sig := <-sigs:
		log.Printf("terminating: %v", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	return s.Shutdown(ctx)
}