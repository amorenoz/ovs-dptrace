# ovs-dptrace
OpenvSwitch kernel datapath tracing tool based on [ebpf](https://github.com/cilium/ebpf/).
It helps visualize actions and upcalls made by the kernel datapath.

## Features
- CO-RE single binary
- L2, L3, L4 header filtering
- Save samples for offline processing

## Requirements
- Linux kernel >= 1.14 (asuming the in-tree openvswitch kernel module is used)

## Build
```
make
```
### Build requirements
- bpftool
- golang

## Usage
Visualize life events:
```
ovs-dptrace -filter 'proto tcp'
666700664705504 | p2_l UPCALL: TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xe6f1beaf
666700665288097 | p2_l ACTION (HASH): TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xe6f1beaf
666700665313641 | p2_l ACTION (RECIRC): TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xe6f1beaf
666700665318955 | p2_lp2_l UPCALL: TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xe6f1beaf
666700665524391 | p2_l ACTION (OUTPUT): TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xe6f1beaf
666701668001799 | p2_l ACTION (HASH): TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xc7257de2
666701668027419 | p2_l ACTION (RECIRC): TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xc7257de2
666701668032677 | p2_lp2_l UPCALL: TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xc7257de2
666701668287302 | p2_l ACTION (OUTPUT): TCP(49450 -> 2399 [seq=15039 seq_ack=0] [SYN]) hash 0xc7257de2
^C
Event count:
UPCALL: 6
ACTION: 12
```

Save events for offline visualization
```
ovs-dptrace -output samples.data
^C
Written 12 samples
```
Visualize previously saved samples:
```
ovs-dptrace -input samples.data
666886611499599 | p2_l ACTION (HASH): TCP(49454 -> 2399 [seq=52003 seq_ack=0] [SYN]) hash 0x9d1dab7e
...
Event count:
UPCALL: 3
ACTION: 9
```
