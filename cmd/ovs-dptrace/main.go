package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var filterExpr = flag.String("filter", "", "Specify a filter expression based on iface, etype, proto, dst, src and tcpflag")

var outputFile = flag.String("output", "", "Specify a file to write events to")
var inputFile = flag.String("input", "", "Specify a file to read events from instead from live capturing")

var processor EventProcessor
var reader EventReader
var stopper = make(chan os.Signal, 1)
var wg sync.WaitGroup

func main() {
	var err error
	// Subscribe to signals for terminating the program.
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	flag.Parse()
	if *outputFile != "" {
		processor, err = NewEventWriter(*outputFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		processor, err = NewEventPrinter()
		if err != nil {
			log.Fatal(err)
		}
	}
	if *inputFile != "" {
		reader, err = NewFileReader(*inputFile)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		reader, err = NewEbpfReader(*filterExpr)
		if err != nil {
			log.Fatal(err)
		}
	}

	wg.Add(1)
	go func() {
		<-stopper
		defer wg.Done()
		err := reader.Destroy()
		if err != nil {
			log.Printf("Error destroying reader: %s", err)
		}
		report, err := processor.Report()
		if err != nil {
			log.Printf("Error creating report: %s", err)
		} else {
			fmt.Printf("\n")
			fmt.Printf(report)
		}
		err = processor.Destroy()
		if err != nil {
			log.Printf("Error destroying processor: %s", err)
		}
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			log.Printf("reading from reader: %s", err)
		}
		if record == nil {
			//log.Println("Exiting...")
			break
		}
		err = processor.Process(record)
		if err != nil {
			log.Fatal(err)
		}
	}
	stopper <- os.Interrupt
	wg.Wait()
}
