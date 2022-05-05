package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/amorenoz/ovs-dptrace/pkg/ovstrace"
)

type EventProcessor interface {
	Process([]byte) error
	Report() (string, error)
	Destroy() error
}

/* eventPrinter prints events in stdout */
type eventPrinter struct {
	count map[ovstrace.EventType]uint64
}

func NewEventPrinter() (EventProcessor, error) {
	printer := &eventPrinter{
		count: make(map[ovstrace.EventType]uint64),
	}
	printer.count[ovstrace.EventUpcall] = 0
	printer.count[ovstrace.EventAction] = 0
	return printer, nil
}

func (p *eventPrinter) Process(sample []byte) error {
	event, err := ovstrace.EventFromBytes(bytes.NewBuffer(sample))
	if err != nil {
		return err
	}
	p.count[event.Type]++
	fmt.Println(event.String())
	return nil
}

func (p *eventPrinter) Report() (string, error) {
	var report string
	report += fmt.Sprintf("Event count:\n")
	report += fmt.Sprintf("UPCALL: %d\n", p.count[ovstrace.EventUpcall])
	report += fmt.Sprintf("ACTION: %d\n", p.count[ovstrace.EventAction])
	return report, nil
}

func (p *eventPrinter) Destroy() error {
	return nil
}

/* eventWriter writes raw events in a file */
type eventWriter struct {
	file  *os.File
	count uint64
}

func NewEventWriter(filename string) (EventProcessor, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return &eventWriter{
		file:  file,
		count: 0,
	}, nil
}

func (p *eventWriter) Process(sample []byte) error {
	if _, err := p.file.Write(sample); err != nil {
		return err
	}
	p.count++
	return nil
}

func (p *eventWriter) Report() (string, error) {
	report := fmt.Sprintf("Written %d samples", p.count)
	return report, nil
}

func (w *eventWriter) Destroy() error {
	w.file.Close()
	return nil
}
