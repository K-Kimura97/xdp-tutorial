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

static __always_inline int srv6_encap(struct xdp_md *ctx,
                struct ethhdr *eth)
{
	void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_cpy;
    struct ipv6hdr *outerip6h;
    struct ipv6hdr *innerip6h;
	struct ipv6hdr ip6h_cpy;
 	struct ipv6_sr_hdr *srh;
	struct in6_addr *seg_item;
	__u8 innerlen;
	
	struct in6_addr outer_dst_ipv6 = {
        .in6_u = {
            .u6_addr8 = {
				//2406:da14:a33:1c01:9a1b:cdcb:66fa:ec0e
                0x24, 0x06, 0xda, 0x14, 0x0a, 0x33, 0x1c, 0x01,
                0x9a, 0x1b, 0xcd, 0xcb, 0x66, 0xfa, 0xec, 0x0e,
            }
        }
    };

/*
        struct in6_addr outer_src_ipv6 = {
                .in6_u = {
                        .u6_addr8 = {
                        0x24, 0x06, 0xda, 0x14, 0x0a, 0x33, 0x1c, 0x01,
                        0x9a, 0x1b, 0xcd, 0xcb, 0x66, 0xfa, 0xec, 0x0e,
                        }
                }
        };
*/

	if (eth + 1 > data_end)
        return -1;

    /* First copy the original Ethernet header */
    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	innerip6h = (void *)(eth + 1);
	if (innerip6h + 1 > data_end)
		return -1;
	innerlen = bpf_ntohs(innerip6h->payload_len);
	__builtin_memcpy(&ip6h_cpy, innerip6h, sizeof(ip6h_cpy));

    /* Then add space in front of the packet */
    if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*outerip6h) - (int)sizeof(*srh)) - (int)sizeof(*seg_item))
        return -1;
	
    /* Need to re-evaluate data_end and data after head adjustment, and
     * bounds check, even though we know there is enough space (as we
     * increased it).
     */
    data_end = (void *)(long)ctx->data_end;
    eth = (void *)(long)ctx->data;

    /* Copy back Ethernet header in the right place, populate VLAN tag with
     * ID and proto, and set outer Ethernet header to VLAN type.
     */
	if (eth + 1 > data_end)
        return -1;
    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
	eth->h_proto = bpf_htons(ETH_P_IPV6);

	outerip6h = (void *)(eth + 1);
    if (outerip6h + 1 > data_end)
        return -1;
	__builtin_memcpy(outerip6h, &ip6h_cpy, sizeof(ip6h_cpy));
/*
	if ((void*)&outerip6h->daddr + sizeof(struct in6_addr) > data_end)
                return -1;
*/
	__builtin_memcpy(&outerip6h->daddr, &outer_dst_ipv6, sizeof(outer_dst_ipv6));

	outerip6h->version=6;
	outerip6h->priority=0;
	outerip6h->nexthdr = NEXTHDR_ROUTING;
	outerip6h->hop_limit = 64;
	outerip6h->payload_len = bpf_htons(innerlen + sizeof(*outerip6h) + sizeof(*srh) + sizeof(struct in6_addr));

	srh = (void *)outerip6h + sizeof(struct ipv6hdr);
	if (srh + 1 > data_end)
        return -1;
	srh->nexthdr = IPPROTO_IPV6;
    srh->hdrlen = (sizeof(*srh) + sizeof(*seg_item))/8 - 1;
    srh->type = 4;
    srh->segments_left = 0;//0
    srh->first_segment = 0;//0
    srh->flags = 0;
	
	seg_item = (void *)(srh + 1);
    if (seg_item + 1 > data_end)
        return -1;
	__builtin_memcpy(seg_item, &outer_dst_ipv6, sizeof(struct in6_addr));

/*
	if ((void *)(&srh->segments[0] + 1) > data_end)
		return -1;
//	__builtin_memcpy(&srh->segments[0], &seg_item, sizeof(struct in6_addr));
	srh->segments[0] = *seg_item;
*/
	//	__builtin_memcpy(&outerip6h->saddr, &outer_src_ipv6, sizeof(outer_src_ipv6));
	//__builtin_memcpy(&(outerip6h->saddr), &outer_src_ipv6, sizeof(struct in6_addr));
	//__builtin_memcpy(&outerip6h->daddr, &outer_dst_ipv6, sizeof(struct in6_addr));

    return 0;
}

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

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	} else {
		goto out;
	}

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
	
out:
	return xdp_stats_record_action(ctx, action);
}

/*
 * Solution to the assignments 2 and 3 in lesson packet02: Will pop outermost
 * VLAN tag if it exists, otherwise push a new one with ID 1
 */
SEC("xdp_vlan_swap")
int xdp_vlan_swap_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type < 0)
		return XDP_PASS;

	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

SEC("xdp_srv6_encap")
int xdp_srv6_encap_func(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* These keep track of the next header type and iterator pointer */
    struct hdr_cursor nh;
    int nh_type;
    nh.pos = data;

    struct ethhdr *eth;
    nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type < 0)
        return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IPV6)){
        srv6_encap(ctx, eth);
		//return XDP_TX;
	}

        return XDP_PASS;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";