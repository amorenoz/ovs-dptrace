all: ovs-dptrace

ovs-dptrace: ovstrace
	rm -rf cmd/ovs-dptrace/bpf
	cp -r pkg/ovstrace/bpf cmd/ovs-dptrace/bpf
	go generate cmd/ovs-dptrace/probe.go
	go build ./cmd/ovs-dptrace

probes: ovstrace

ovstrace:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ovstrace/bpf/vmlinux.h

