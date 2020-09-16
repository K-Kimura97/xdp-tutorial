/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/socket.h>
#include <linux/seg6.h>
#include <linux/seg6_local.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

// net/ipv6.h
#define NEXTHDR_IPV6 41
#define NEXTHDR_ROUTING		43	/* Routing header. */
​
static __always_inline int srv6_encap(struct xdp_md *ctx,
                struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr eth_cpy;
        struct ipv6hdr *outerip6h;
        struct ipv6hdr *innerip6h;
​
        /* First copy the original Ethernet header */
        __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));
​
        /* Then add space in front of the packet */
        if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*outerip6h)))
                return -1;
​
        /* Need to re-evaluate data_end and data after head adjustment, and
         * bounds check, even though we know there is enough space (as we
         * increased it).
         */
        data_end = (void *)(long)ctx->data_end;
        eth = (void *)(long)ctx->data;
​
        if (eth + 1 > data_end)
                return -1;
​
        /* Copy back Ethernet header in the right place, populate VLAN tag with
         * ID and proto, and set outer Ethernet header to VLAN type.
         */
        __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
​
        outerip6h = (void *)(eth + 1);
​
        if (outerip6h + 1 > data_end)
                return -1;
​
        innerip6h = (void *)(outerip6h + 1);
​
	if (innerip6h +1 > data_end)
		return -1;
​
	__u8 innerlen;
​
	
	struct in6_addr outer_dst_ipv6 = {
                .in6_u = {
                        .u6_addr8 = {
                        0x24, 0x06, 0xda, 0x14, 0x0a, 0x6f, 0x78, 0x01,
                        0xb7, 0xb8, 0x62, 0x29, 0xe0, 0x26, 0x05, 0x71,
                        }
                }
        };
​
	/*
        struct in6_addr outer_src_ipv6 = {
                .in6_u = {
                        .u6_addr8 = {
                        0x24, 0x06, 0xda, 0x14, 0x0a, 0x6f, 0x78, 0x01,
                        0xca, 0x97, 0x06, 0xf9, 0xb2, 0x74, 0xc6, 0x42,
                        }
                }
        };*/
​
​
    __builtin_memcpy(outerip6h, innerip6h, sizeof(*innerip6h));
	innerlen = bpf_ntohs(innerip6h->payload_len);
	//__builtin_memcpy(&outerip6h->saddr, &outer_src_ipv6, sizeof(outer_src_ipv6));
	__builtin_memcpy(&outerip6h->daddr, &outer_dst_ipv6, sizeof(outer_dst_ipv6));
	outerip6h->version=6;
	outerip6h->priority=0;
	outerip6h->nexthdr = NEXTHDR_IPV6;
	outerip6h->hop_limit = 64;
	outerip6h->payload_len = bpf_htons(innerlen + sizeof(*outerip6h));
	//__builtin_memcpy(&(outerip6h->saddr), &outer_src_ipv6, sizeof(struct in6_addr));
	//__builtin_memcpy(&outerip6h->daddr, &outer_dst_ipv6, sizeof(struct in6_addr));
​
        eth->h_proto = bpf_htons(ETH_P_IPV6);
        return 0;
}
​
​
/*
 * Solution to the assignment 1 in lesson packet02
 */
SEC("xdp_patch_ports")
int xdp_patch_ports_func(struct xdp_md *ctx)
{
	int action = XDP_PASS;
	int eth_type, ip_type;
	struct ethhdr *eth;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	struct udphdr *udphdr;
	struct tcphdr *tcphdr;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
​
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}
​
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}
​
	if (ip_type == IPPROTO_UDP) {
		if (parse_udphdr(&nh, data_end, &udphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		udphdr->dest = bpf_htons(bpf_ntohs(udphdr->dest) - 1);
	} else if (ip_type == IPPROTO_TCP) {
		if (parse_tcphdr(&nh, data_end, &tcphdr) < 0) {
			action = XDP_ABORTED;
			goto out;
		}
		tcphdr->dest = bpf_htons(bpf_ntohs(tcphdr->dest) - 1);
	}
​
out:
	return xdp_stats_record_action(ctx, action);
}
​
/*
 * Solution to the assignments 2 and 3 in lesson packet02: Will pop outermost
 * VLAN tag if it exists, otherwise push a new one with ID 1
 */
SEC("xdp_vlan_swap")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
​
	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;
​
	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;
​
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);
​
	return XDP_PASS;
}
​
SEC("xdp_srv6_encap")
int xdp_srv6_encap_func(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
​
        /* These keep track of the next header type and iterator pointer */
        struct hdr_cursor nh;
        int nh_type;
        nh.pos = data;
​
        struct ethhdr *eth;
        nh_type = parse_ethhdr(&nh, data_end, &eth);
        if (nh_type < 0)
                return XDP_PASS;
​
	if (eth->h_proto == bpf_htons(ETH_P_IPV6))
                srv6_encap(ctx, eth);
​
        return XDP_PASS;
}
​
SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}
​
char _license[] SEC("license") = "GPL";