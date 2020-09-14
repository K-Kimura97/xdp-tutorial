/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

struct bpf_map_def SEC("maps") transit_table_v4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct transit_behavior),
    .max_entries = MAX_TRANSIT_ENTRIES,
};

/*パケットのチェック*/
static inline struct iphdr *get_ipv4(struct xdp_md *xdp)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;

    struct iphdr *iph = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) > data_end) {
        return NULL;
    }

    if (iph + 1 > data_end) {
        return NULL;
    }

    return iph;
};

struct gtp1hdr { /* According to 3GPP TS 29.060. */
    __u8 flags;
    __u8 type;
    __u16 length;
    __u32 tid;
    //u16 seqNum;
};

/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or -1 on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth)
{
	/*
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;
	__be16 h_proto;
	*/
	int vlid = -1;

	/* Check if there is a vlan tag to pop */

	/* Still need to do bounds checking */

	/* Save vlan ID for returning, h_proto for updating Ethernet header */

	/* Make a copy of the outer Ethernet header before we cut it off */

	/* Actually adjust the head pointer */

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */

	/* Copy back the old Ethernet header and update the proto type */


	return vlid;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx,
					 struct ethhdr *eth, int vlid)
{
	return 0;
}

static inline int action_t_gtb4_d(struct xdb_md *xdp, struct ethhdr *eth,
								struct transit_behavior *tb)
{
	void *data_end = (void *)(long)ctx->data_end;//パケットの終点
	struct ethhdr eth_cpy;//パケットの始点
	struct ipv6hdr *hdr;
	struct ipv6_sr_hdr *srh;
	__u8 srh_len;

	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));//イーサネットヘッダのコピー

/*
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))//ポインタの移動
		return -1;
*/
	srh_len = sizeof(struct ipv6_sr_hdr) + sizeof(struct in6_addr) * tb->segment_length;
    if(bpf_xdp_adjust_head(xdp, 0 - (int)(sizeof(struct ipv6hdr) + srh_len))) {
        return XDP_PASS;
    }

	data_end = (void *)(long)xdp->data_end;
	eth = (void *)(long)xdp->data;
	
	if (eth + 1 > data_end)//確認
		return -1;

	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));//更新

	bpf_printk("new seg6 make hdr\n");
	hdr = (void *)(eth + 1);
	if (hdr + 1 > data_end)
		return -1;
	hdr->version = 6;
    hdr->priority = 0;
    hdr->nexthdr = NEXTHDR_ROUTING;
    hdr->hop_limit = 64;
	inner_len = bpf_ntohs(iph->tot_len);//?
    hdr->payload_len = bpf_htons(srh_len + inner_len);//?

	srh = (void *)(hdr + 1);
	if (srh + 1 > data_end)
		return -1;
	srh->nexthdr = IPPROTO_IPIP;
    srh->hdrlen = (srh_len / 8 - 1);
    srh->type = 4;
    srh->segments_left = tb->segment_length - 1;
    srh->first_segment = tb->segment_length - 1;
    srh->flags = 0;

	/*情報の追加*/
/*
	vlh = (void *)(eth + 1);
	if (vlh + 1 > data_end)
		return -1;
	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;
*/

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;

}

/* Implement assignment 1 in this section */
SEC("xdp_port_rewrite")
int xdp_port_rewrite_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

/* VLAN swapper; will pop outermost VLAN tag if it exists, otherwise push a new
 * one with ID 1. Use this for assignments 2 and 3.
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

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(ctx, eth);
	else
		vlan_tag_push(ctx, eth, 1);

	return XDP_PASS;
}

/* Solution to the parsing exercise in lesson packet01. Handles VLANs and legacy
 * IP (via the helpers in parsing_helpers.h).
 */
SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

	/* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;

	struct ethhdr *eth;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);

	if (nh_type == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h;
		struct icmp6hdr *icmp6h;

		nh_type = parse_ip6hdr(&nh, data_end, &ip6h);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6h);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

		if (bpf_ntohs(icmp6h->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;

	} else if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		struct icmphdr *icmph;

		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmph);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmph->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
	}
 out:
	return xdp_stats_record_action(ctx, action);
}

SEC("xdp_prog")
int srv6(struct xdo_md *xdp)
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

	/* Assignment 2 and 3 will implement these. For now they do nothing */
	if (proto_is_vlan(eth->h_proto))
		vlan_tag_pop(xdp, eth);
	else
		vlan_tag_push(xdp, eth, 1);

	tb = bpf_map_lookup_elem(&transit_table_v4, &iph->daddr);
	if(tb -> action == SEG6_IPTUN_MODE_ENCAP_T_M_GTP4_D)
		action_t_gtp4_d(xdp, eth, tb);	

	return XDP_PASS;
		
	}	
}

char _license[] SEC("license") = "GPL";
