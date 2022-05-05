package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/amorenoz/ovs-dptrace/pkg/ovstrace"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type EventReader interface {
	Read() ([]byte, error)
	Destroy() error
}

/* eventPrinter prints events in stdout */
type ebpfReader struct {
	count   map[ovstrace.EventType]uint64
	objs    probeObjects
	ring    *ringbuf.Reader
	upcall  link.Link
	actions link.Link
}

func NewEbpfReader(filterExpr string) (EventReader, error) {
	filter, err := ovstrace.ParseFilter(filterExpr)
	if err != nil {
		return nil, err
	}
	objs := probeObjects{}
	if err := loadProbeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("Error while loading BPF objects (%d)", err)
	}
	if err := objs.ConfigMap.Put(uint64(0), filter); err != nil {
		return nil, err
	}
	rd, err := ringbuf.NewReader(objs.RingBuffer)
	if err != nil {
		return nil, err
	}
	kpu, err := link.Tracepoint("openvswitch", "ovs_dp_upcall", objs.UpcallTracepoint)
	if err != nil {
		return nil, fmt.Errorf("opening tracepoint %s", err)
	}

	kpa, err := link.Tracepoint("openvswitch", "ovs_do_execute_action", objs.ActionTracepoint)
	if err != nil {
		return nil, fmt.Errorf("opening tracepoint %s", err)
	}
	return &ebpfReader{
		count:   make(map[ovstrace.EventType]uint64, 2),
		objs:    objs,
		ring:    rd,
		upcall:  kpu,
		actions: kpa,
	}, nil
}

func (p *ebpfReader) Read() ([]byte, error) {
	record, err := p.ring.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading from reader: %s", err)
	}
	return record.RawSample, nil
}

func (p *ebpfReader) Destroy() error {
	var errors []string
	if err := p.objs.Close(); err != nil {
		errors = append(errors, err.Error())
	}

	if err := p.ring.Close(); err != nil {
		errors = append(errors, err.Error())
	}
	if err := p.actions.Close(); err != nil {
		errors = append(errors, err.Error())
	}
	if err := p.upcall.Close(); err != nil {
		errors = append(errors, err.Error())
	}

	if len(errors) != 0 {
		return fmt.Errorf(strings.Join(errors, " | "))
	}
	return nil
}

/* eventPrinter prints events in stdout */
type fileReader struct {
	count     uint64
	file      *os.File
	eventSize int
}

func NewFileReader(filename string) (EventReader, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	event := ovstrace.EventBytes{}

	return &fileReader{
		file:      file,
		count:     0,
		eventSize: binary.Size(event),
	}, nil
}

func (p *fileReader) Read() ([]byte, error) {
	sample := make([]byte, p.eventSize)
	read, err := p.file.Read(sample)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading from reader: %s", err)
	}
	if read != p.eventSize {
		return nil, fmt.Errorf("Read %d bytes", read)
	}
	return sample, nil
}

func (p *fileReader) Destroy() error {
	if err := p.file.Close(); err != nil {
		return err
	}
	return nil
}
