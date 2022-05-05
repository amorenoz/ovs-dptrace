#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define EVENT_TYPE_UPCALL 0
#define EVENT_TYPE_ACTION 1

#define DEV_NAME_MAX 64

/* from bcc/src/cc/export/helpers.h */
#define TP_DATA_LOC_READ_CONST(dst, field, length)                        \
        do {                                                              \
            unsigned short __offset = args->data_loc_##field & 0xFFFF;    \
            bpf_probe_read((void *)dst, length, (char *)args + __offset); \
        } while (0);


#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x)		__builtin_bswap16(x)
#define bpf_htons(x)		__builtin_bswap16(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && \
	__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x)		(x)
#define bpf_htons(x)		(x)
#else
# error "Endianness detection needs to be set up for your compiler?!"
#endif

#define TERNARY_FIELD(_t, name)	\
	_t name;		\
	_t name ## _mask;

#define ternary_match(val1, val2, mask)					        \
{									                            \
	u8 *p1 = (u8 *)&val1, *p2 = (u8 *)&val2, *pm = (u8 *)&mask;	\
	int sz = sizeof(typeof(val1));					            \
	for (; sz > 0; sz--) {						                \
		if (*pm && (*p1 & *pm) != *p2)				            \
			return false;					                    \
		p1++, p2++, pm++;					                    \
	}								                            \
}

#define string_match(value, filter, size)                       \
{                                                               \
    if (filter[0] != '\0') {                                    \
        for (int i = 0; i < size; i++) {                        \
            if (value[i] != filter[i]) {                        \
                return false;                                   \
            }                                                   \
        }                                                       \
    }                                                           \
}

struct filter {
	//u32 mark;
	TERNARY_FIELD(struct ethhdr,  eth)
	TERNARY_FIELD(struct iphdr,   ipv4)
	TERNARY_FIELD(struct ipv6hdr, ipv6)
	TERNARY_FIELD(struct tcphdr,  tcp)
	TERNARY_FIELD(struct udphdr,  udp)
    char dev_name[DEV_NAME_MAX];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u64);
	__type(value, struct filter);
} config_map SEC(".maps");


struct event {
	u64  timestamp;
    u8   type;
    u8   subaction_type; // action_type or upcall_cmd
    char dev_name[DEV_NAME_MAX];
    u32  hash;
    u16  sport;
    u16  dport;
    u32  seq;
    u32  ack_seq;
    u8   tcpflags;
    u8   protocol;
    u8   ip_version;
} __attribute__((packed));

struct  {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} ring_buffer SEC(".maps");


static __always_inline bool
event_fill_skb(struct event *event, struct sk_buff *skb,
               struct filter *filter)
{
    unsigned char *pos, *head;
    u16 network, transport, mac;
	struct ethhdr eth;

    if (!skb) {
        return false;
    }

    head = BPF_CORE_READ(skb, head);
	mac = BPF_CORE_READ(skb, mac_header);
    network = BPF_CORE_READ(skb, network_header);
    transport = BPF_CORE_READ(skb, transport_header);

	/* L2 */
	pos = head + mac;
	bpf_probe_read_kernel(&eth, sizeof(struct ethhdr), pos);
	ternary_match(eth, filter->eth, filter->eth_mask)


    pos = head + network;
    bpf_probe_read_kernel(&event->ip_version, sizeof(event->ip_version), pos);
    event->ip_version >>= 4;

    /* L3 */
    if (event->ip_version == 4) {
        struct iphdr ip4;

        bpf_probe_read_kernel(&ip4, sizeof(ip4), pos);
		ternary_match(ip4, filter->ipv4, filter->ipv4_mask)

        event->protocol = ip4.protocol;
    } else if (event->ip_version == 6) {
        struct ipv6hdr ip6;

        bpf_probe_read_kernel(&ip6, sizeof(ip6), pos);
		ternary_match(ip6, filter->ipv6, filter->ipv6_mask)
        /* TODO: support IPv6 extension headers? */

        event->protocol = ip6.nexthdr;
    } else {
        return false;
    }

    /* Take L4 header info */
    pos = head + transport;
    if (event->protocol == IPPROTO_TCP) {
        struct tcphdr tcp;

        bpf_core_read(&tcp, sizeof(tcp), pos);
		ternary_match(tcp, filter->tcp, filter->tcp_mask)

        event->seq = bpf_ntohs(tcp.seq);
        event->ack_seq = bpf_ntohs(tcp.ack_seq);
        event->dport = bpf_ntohs(tcp.dest);
        event->sport = bpf_ntohs(tcp.source);
        bpf_core_read(&event->tcpflags, 1, ((uint8_t*)&tcp) + 13);
    } else if (event->protocol == IPPROTO_UDP) {
        struct udphdr udp;

        bpf_core_read(&udp, sizeof(udp), pos);
		ternary_match(udp, filter->udp, filter->udp_mask)

        event->dport = bpf_ntohs(udp.dest);
        event->sport = bpf_ntohs(udp.source);
    }

    /* Hash data */
    event->hash = BPF_CORE_READ(skb, hash);

    return true;
}


struct ovs_do_execute_action_args {
        u64 __do_not_use__;
        void * dpaddr;
        int data_loc_dp_name;
        int data_loc_dev_name;
        void * skbaddr;
        unsigned int len;
        unsigned int data_len;
        unsigned int truesize;
        u8 nr_frags;
        char __pad_45;
        u16 gso_size;
        u16 gso_type;
        char __pad_50;
        char __pad_51;
        u32 ovs_flow_hash;
        u32 recirc_id;
        char __pad_60;
        char __pad_61;
        char __pad_62;
        char __pad_63;
        void * keyaddr;
        u16 key_eth_type;
        u8 key_ct_state;
        u8 key_ct_orig_proto;
        u16 key_ct_zone;
        char __pad_78;
        char __pad_79;
        unsigned int flow_key_valid;
        u8 action_type;
        char __pad_85;
        char __pad_86;
        char __pad_87;
        unsigned int action_len;
        char __pad_92;
        char __pad_93;
        char __pad_94;
        char __pad_95;
        void * action_data;
        u8 is_last;
};

SEC("tracepoint/openvswitch/ovs_do_execute_action")
int action_tracepoint(struct ovs_do_execute_action_args *args) {
    struct sk_buff *skb;
    struct filter *filter;
    struct event event = {};
    u64 zero = 0;

	filter = bpf_map_lookup_elem(&config_map, &zero);
    if (!filter) {
        return 0;
    }

    TP_DATA_LOC_READ_CONST(&event.dev_name, dev_name,
                           sizeof(event.dev_name));

    string_match(event.dev_name, filter->dev_name, DEV_NAME_MAX);

	event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_ACTION;
    event.subaction_type = args->action_type;

    //bpf_probe_read_kernel_str(&event.dev_name, sizeof(event.dev_name), args->dev_name);
    skb = (struct sk_buff*) args->skbaddr;

    if (event_fill_skb(&event, skb, filter)) {
		bpf_ringbuf_output(&ring_buffer, &event, sizeof(event), 0);
    }

    return 0;
}


struct ovs_dp_upcall_args {
        u64 __do_not_use__;
        void * dpaddr;
        int data_loc_dp_name;
        int data_loc_dev_name;
        void * skbaddr;
        unsigned int len;
        unsigned int data_len;
        unsigned int truesize;
        u8 nr_frags;
        char __pad_45;
        u16 gso_size;
        u16 gso_type;
        char __pad_50;
        char __pad_51;
        u32 ovs_flow_hash;
        u32 recirc_id;
        char __pad_60;
        char __pad_61;
        char __pad_62;
        char __pad_63;
        const void * keyaddr;
        u16 key_eth_type;
        u8 key_ct_state;
        u8 key_ct_orig_proto;
        u16 key_ct_zone;
        char __pad_78;
        char __pad_79;
        unsigned int flow_key_valid;
        u8 upcall_cmd;
        char __pad_85;
        char __pad_86;
        char __pad_87;
        u32 upcall_port;
        u16 upcall_mru;
};
SEC("tracepoint/openvswitch/ovs_dp_upcall")
int upcall_tracepoint(struct ovs_dp_upcall_args *args) {
    struct sk_buff *skb;
    struct filter *filter;
    struct event event = {};
    u64 zero = 0;

	filter = bpf_map_lookup_elem(&config_map, &zero);
    if (!filter) {
        return 0;
    }

    TP_DATA_LOC_READ_CONST(&event.dev_name, dev_name,
                           sizeof(event.dev_name));

    string_match(event.dev_name, filter->dev_name, DEV_NAME_MAX)

	event.timestamp = bpf_ktime_get_ns();
    event.type = EVENT_TYPE_UPCALL;
    event.subaction_type = args->upcall_cmd;

    skb = (struct sk_buff*) args->skbaddr;

    if (event_fill_skb(&event, skb, filter)) {
		bpf_ringbuf_output(&ring_buffer, &event, sizeof(event), 0);
    }

    return 0;
}

char __license[] SEC("license") = "GPL";
