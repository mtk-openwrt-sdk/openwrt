/*   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 2 of the License
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   Copyright (C) 2014-2016 Sean Wang <sean.wang@mediatek.com>
 *   Copyright (C) 2016-2017 John Crispin <blogic@openwrt.org>
 */

#include <linux/netfilter_bridge.h>
#include <linux/netfilter_ipv6.h>

#include <net/arp.h>
#include <net/neighbour.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "nf_hnat_mtk.h"
#include "hnat.h"

#include "../mtk_eth_soc.h"

#define do_ge2ext_fast(dev, skb)                                               \
	((IS_LAN(dev) || IS_WAN(dev)) && skb_hnat_is_hashed(skb) &&            \
	 skb_hnat_reason(skb) == HIT_BIND_FORCE_TO_CPU)
#define do_ext2ge_fast_learn(dev, skb)                                         \
	(IS_PPD(dev) &&                                                        \
	 (skb_hnat_sport(skb) == NR_PDMA_PORT ||                               \
	  skb_hnat_sport(skb) == NR_QDMA_PORT))

static inline uint8_t get_wifi_hook_if_index_from_dev(const struct net_device *dev)
{
	int i;

	for (i = 1; i < MAX_IF_NUM; i++) {
		if (wifi_hook_if[i] == dev)
			return i;
	}

	return 0;
}

static inline int get_ext_device_number(void)
{
	int i, number = 0;

	for (i = 0; i < MAX_EXT_DEVS && ext_if[i]; i++)
		number += 1;
	return number;
}

static inline int get_index_from_devname(const char *name)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && ext_if[i]; i++) {
		ext_entry = ext_if[i];
		if (!strcmp(name, ext_entry->name) && ext_entry->dev)
			return ext_entry->dev->ifindex;
	}
	return 0;
}

static inline int get_index_from_dev(const struct net_device *dev)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && ext_if[i]; i++) {
		ext_entry = ext_if[i];
		if (dev == ext_entry->dev)
			return ext_entry->dev->ifindex;
	}
	return 0;
}

static inline struct net_device *get_dev_from_index(int index)
{
	int i;
	struct extdev_entry *ext_entry;
	struct net_device *dev = 0;

	for (i = 0; i < MAX_EXT_DEVS && ext_if[i]; i++) {
		ext_entry = ext_if[i];
		if (ext_entry->dev && index == ext_entry->dev->ifindex) {
			dev = ext_entry->dev;
			break;
		}
	}
	return dev;
}

static inline int extif_set_dev(struct net_device *dev)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && ext_if[i]; i++) {
		ext_entry = ext_if[i];
		if (!strcmp(dev->name, ext_entry->name) && !ext_entry->dev) {
			dev_hold(dev);
			ext_entry->dev = dev;
			pr_info("%s(%s)\n", __func__, dev->name);

			return ext_entry->dev->ifindex;
		}
	}

	return 0;
}

static inline int extif_put_dev(struct net_device *dev)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 0; i < MAX_EXT_DEVS && ext_if[i]; i++) {
		ext_entry = ext_if[i];
		if (ext_entry->dev == dev) {
			ext_entry->dev = NULL;
			dev_put(dev);
			pr_info("%s(%s)\n", __func__, dev->name);

			return ext_entry->dev->ifindex;
		}
	}

	return 0;
}

int ext_if_add(struct extdev_entry *ext_entry)
{
	int len = get_ext_device_number();

	ext_if[len++] = ext_entry;
	return len;
}

int ext_if_del(struct extdev_entry *ext_entry)
{
	int i, j;

	for (i = 0; i < MAX_EXT_DEVS; i++) {
		if (ext_if[i] == ext_entry) {
			for (j = i; ext_if[j] && j < MAX_EXT_DEVS - 1; j++)
				ext_if[j] = ext_if[j + 1];
			ext_if[j] = NULL;
			break;
		}
	}

	return i;
}

void foe_clear_all_bind_entries(struct net_device *dev)
{
	int hash_index;
	struct foe_entry *entry;

	if (!IS_LAN(dev) && !IS_WAN(dev) &&
	    !get_index_from_devname(dev->name) &&
	    !dev->netdev_ops->ndo_hnat_check)
		return;

	cr_set_field(host->ppe_base + PPE_TB_CFG, SMA, SMA_ONLY_FWD_CPU);
	for (hash_index = 0; hash_index < foe_etry_num; hash_index++) {
		entry = host->foe_table_cpu + hash_index;
		if (entry->bfib1.state == BIND) {
			entry->ipv4_hnapt.udib1.state = INVALID;
			entry->ipv4_hnapt.udib1.time_stamp =
				readl((host->fe_base + 0x0010)) & 0xFF;
		}
	}

	/* clear HWNAT cache */
	cr_set_field(host->ppe_base + PPE_CAH_CTRL, CAH_X_MODE, 1);
	cr_set_field(host->ppe_base + PPE_CAH_CTRL, CAH_X_MODE, 0);
	cr_set_field(host->ppe_base + PPE_CAH_CTRL, CAH_EN, 1);
	mod_timer(&hnat_sma_build_entry_timer, jiffies + 3 * HZ);
}

int nf_hnat_netdevice_event(struct notifier_block *unused, unsigned long event,
			    void *ptr)
{
	struct net_device *dev;

	dev = netdev_notifier_info_to_dev(ptr);

	switch (event) {
	case NETDEV_UP:
		extif_set_dev(dev);

		break;
	case NETDEV_GOING_DOWN:
		if (!get_wifi_hook_if_index_from_dev(dev))
			extif_put_dev(dev);

		foe_clear_all_bind_entries(dev);

		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

void foe_clear_entry(struct neighbour *neigh)
{
	u32 *daddr = (u32 *)neigh->primary_key;
	unsigned char h_dest[ETH_ALEN];
	struct foe_entry *entry;
	int hash_index;
	u32 dip;

	dip = (u32)(*daddr);

	for (hash_index = 0; hash_index < foe_etry_num; hash_index++) {
		entry = host->foe_table_cpu + hash_index;
		if (entry->bfib1.state == BIND &&
		    entry->ipv4_hnapt.new_dip == ntohl(dip)) {
			*((u32 *)h_dest) = swab32(entry->ipv4_hnapt.dmac_hi);
			*((u16 *)&h_dest[4]) =
				swab16(entry->ipv4_hnapt.dmac_lo);
			if (strncmp(h_dest, neigh->ha, ETH_ALEN) != 0) {
				pr_info("%s: state=%d\n", __func__,
					neigh->nud_state);
				cr_set_field(host->ppe_base + PPE_TB_CFG, SMA,
					     SMA_ONLY_FWD_CPU);

				entry->ipv4_hnapt.udib1.state = INVALID;
				entry->ipv4_hnapt.udib1.time_stamp =
					readl((host->fe_base + 0x0010)) & 0xFF;

				/* clear HWNAT cache */
				cr_set_field(host->ppe_base + PPE_CAH_CTRL,
					     CAH_X_MODE, 1);
				cr_set_field(host->ppe_base + PPE_CAH_CTRL,
					     CAH_X_MODE, 0);
				cr_set_field(host->ppe_base + PPE_CAH_CTRL,
					     CAH_EN, 1);

				mod_timer(&hnat_sma_build_entry_timer,
					  jiffies + 3 * HZ);

				pr_info("Delete old entry: dip =%pI4\n", &dip);
				pr_info("Old mac= %pM\n", h_dest);
				pr_info("New mac= %pM\n", neigh->ha);
			}
		}
	}
}

int nf_hnat_netevent_handler(struct notifier_block *unused, unsigned long event,
			     void *ptr)
{
	struct net_device *dev = NULL;
	struct neighbour *neigh = NULL;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		neigh = ptr;
		dev = neigh->dev;
		if (dev)
			foe_clear_entry(neigh);
		break;
	}

	return NOTIFY_DONE;
}

static void fix_skb_packet_type(struct sk_buff *skb, struct net_device *dev,
				struct ethhdr *eth)
{
	skb->pkt_type = PACKET_HOST;
	if (unlikely(is_multicast_ether_addr(eth->h_dest))) {
		if (ether_addr_equal_64bits(eth->h_dest, dev->broadcast))
			skb->pkt_type = PACKET_BROADCAST;
		else
			skb->pkt_type = PACKET_MULTICAST;
	}
}

unsigned int do_hnat_ext_to_ge(struct sk_buff *skb, const struct net_device *in,
			       const char *func)
{
	skb_set_network_header(skb, 0);
	skb_push(skb, ETH_HLEN);
	set_to_ppe(skb);

	/*set where we come from*/
	skb->vlan_proto = htons(ETH_P_8021Q);
	skb->vlan_tci |=
		(VLAN_TAG_PRESENT | (in->ifindex & VLAN_VID_MASK));
	trace_printk(
		"%s: vlan_prot=0x%x, vlan_tci=%x, in->name=%s, skb->dev->name=%s\n",
		__func__, ntohs(skb->vlan_proto), skb->vlan_tci,
		in->name, g_ppdev->name);
	skb->dev = g_ppdev;
	dev_queue_xmit(skb);
	trace_printk("%s: called from %s successfully\n", __func__, func);
	return 0;
}

unsigned int do_hnat_ext_to_ge2(struct sk_buff *skb, const char *func)
{
	struct ethhdr *eth = eth_hdr(skb);
	struct net_device *dev;

	trace_printk("%s: vlan_prot=0x%x, vlan_tci=%x\n", __func__,
		     ntohs(skb->vlan_proto), skb->vlan_tci);

	dev = get_dev_from_index(skb->vlan_tci & VLAN_VID_MASK);

	if (dev) {
		/*set where we to go*/
		skb->dev = dev;
		skb->vlan_proto = 0;
		skb->vlan_tci = 0;
		set_from_extge(skb);
		fix_skb_packet_type(skb, skb->dev, eth);
		netif_rx(skb);
		trace_printk("%s: called from %s successfully\n", __func__,
			     func);
		return 0;
	}
	trace_printk("%s: called from %s fail\n", __func__, func);
	return -1;
}

unsigned int do_hnat_ge_to_ext(struct sk_buff *skb, const char *func)
{
	/*set where we to go*/
	u8 index;
	struct foe_entry *entry;

	entry = &host->foe_table_cpu[skb_hnat_entry(skb)];
	index = entry->ipv4_hnapt.act_dp;
	skb->dev = get_dev_from_index(index);

#if defined(CONFIG_NET_MEDIATEK_HW_QOS)
	if (eth_hdr(skb)->h_proto == 0x5678) {
		skb = skb_unshare(skb, GFP_ATOMIC);
		if (!skb)
			return NF_ACCEPT;

		if (unlikely(!pskb_may_pull(skb, VLAN_HLEN)))
			return NF_ACCEPT;

		skb_pull_rcsum(skb, VLAN_HLEN);

		memmove(skb->data - ETH_HLEN, skb->data - ETH_HLEN - VLAN_HLEN,
			2 * ETH_ALEN);
	}
#endif

	if (skb->dev) {
		skb_set_network_header(skb, 0);
		skb_push(skb, ETH_HLEN);
		dev_queue_xmit(skb);
		trace_printk("%s: called from %s successfully\n", __func__,
			     func);
		return 0;
	}
	/*if external devices is down, invalidate related ppe entry*/
	if (entry_hnat_is_bound(entry)) {
		entry->bfib1.state = INVALID;
		entry->ipv4_hnapt.act_dp = 0;
	}
	trace_printk("%s: called from %s fail, index=%x\n", __func__,
		     func, index);
	return -1;
}

static void pre_routing_print(struct sk_buff *skb, const struct net_device *in,
			      const struct net_device *out, const char *func)
{
	trace_printk(
		"[%s]: %s(iif=0x%x CB2=0x%x)-->%s (ppe_hash=0x%x) sport=0x%x reason=0x%x alg=0x%x from %s\n",
		__func__, in->name, HNAT_SKB_CB(skb)->iif,
		HNAT_SKB_CB2(skb)->magic, out->name, skb_hnat_entry(skb),
		skb_hnat_sport(skb), skb_hnat_reason(skb), skb_hnat_alg(skb),
		func);
}

static void post_routing_print(struct sk_buff *skb, const struct net_device *in,
			       const struct net_device *out, const char *func)
{
	trace_printk(
		"[%s]: %s(iif=0x%x, CB2=0x%x)-->%s (ppe_hash=0x%x) sport=0x%x reason=0x%x alg=0x%x from %s\n",
		__func__, in->name, HNAT_SKB_CB(skb)->iif,
		HNAT_SKB_CB2(skb)->magic, out->name, skb_hnat_entry(skb),
		skb_hnat_sport(skb), skb_hnat_reason(skb), skb_hnat_alg(skb),
		func);
}

static inline void hnat_set_iif(const struct nf_hook_state *state,
				struct sk_buff *skb)
{
	if (IS_LAN(state->in)) {
		HNAT_SKB_CB(skb)->iif = FOE_MAGIC_GE_LAN;
	} else if (IS_EXT(state->in)) {
		HNAT_SKB_CB(skb)->iif = FOE_MAGIC_EXT;
	} else if (IS_WAN(state->in)) {
		HNAT_SKB_CB(skb)->iif = FOE_MAGIC_GE_WAN;
	} else if (state->in->netdev_ops->ndo_hnat_check) {
		HNAT_SKB_CB(skb)->iif = FOE_MAGIC_GE_VIRTUAL;
	} else if (!IS_BR(state->in)) {
		HNAT_SKB_CB(skb)->iif = FOE_INVALID;

		if (IS_SPACE_AVAILABLE_HEAD(skb))
			memset(skb_hnat_info(skb), 0, FOE_INFO_LEN);
	}
}

static unsigned int
mtk_hnat_ipv4_nf_pre_routing(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	hnat_set_iif(state, skb);

	pre_routing_print(skb, state->in, state->out, __func__);

	/* packets from external devices -> xxx ,step 1 , learning stage & bound stage*/
	if (do_ext2ge_fast_try(state->in, skb)) {
		if (!do_hnat_ext_to_ge(skb, state->in, __func__))
			return NF_STOLEN;
		else
			return NF_ACCEPT;
	}

	/* packets form ge -> external device
	 * For standalone wan interface
	 */
	if (do_ge2ext_fast(state->in, skb)) {
		if (!do_hnat_ge_to_ext(skb, __func__))
			return NF_STOLEN;
		dev_info(host->dev, "%s:drop\n", __func__);
		return NF_DROP;
	}

	return NF_ACCEPT;
}

static unsigned int
mtk_hnat_br_nf_pre_routing(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
#if defined(CONFIG_NET_MEDIATEK_HW_QOS)
	struct foe_entry *entry;
	struct vlan_ethhdr *veth;

	veth = (struct vlan_ethhdr *)skb_mac_header(skb);

	if (eth_hdr(skb)->h_proto == 0x5678) {
		skb_hnat_entry(skb) = ntohs(veth->h_vlan_TCI) & 0x3fff;
		skb_hnat_reason(skb) = HIT_BIND_FORCE_TO_CPU;
	}
#endif

	hnat_set_iif(state, skb);

	pre_routing_print(skb, state->in, state->out, __func__);

	if (unlikely(debug_level >= 7)) {
		hnat_cpu_reason_cnt(skb);
		if (skb_hnat_reason(skb) == dbg_cpu_reason)
			foe_dump_pkt(skb);
	}

	/* packets from external devices -> xxx ,step 1 , learning stage & bound stage*/
	if ((HNAT_SKB_CB(skb)->iif == FOE_MAGIC_EXT) && !is_from_extge(skb)) {
		do_hnat_ext_to_ge(skb, state->in, __func__);
		return NF_STOLEN;
	}

	if (HNAT_SKB_CB(skb)->iif == FOE_MAGIC_EXT)
		clr_from_extge(skb);

	/* packets from external devices -> xxx ,step 2, learning stage */
#if defined(CONFIG_NET_MEDIATEK_HW_QOS)
	entry = &host->foe_table_cpu[skb_hnat_entry(skb)];
	if (do_ext2ge_fast_learn(state->in, skb) && entry->bfib1.state != BIND) {
#else
	if (do_ext2ge_fast_learn(state->in, skb)) {
#endif
		if (!do_hnat_ext_to_ge2(skb, __func__))
			return NF_STOLEN;
		goto drop;
	}

	/* packets form ge -> external device */
	if (do_ge2ext_fast(state->in, skb)) {
		if (!do_hnat_ge_to_ext(skb, __func__))
			return NF_STOLEN;
		goto drop;
	}

	return NF_ACCEPT;
drop:
	dev_info(host->dev, "%s:drop\n", __func__);
	return NF_DROP;
}

static unsigned int hnat_ipv6_get_nexthop(struct sk_buff *skb,
					  const struct net_device *out,
					  struct hnat_hw_path *hw_path)
{
	struct in6_addr *ipv6_nexthop;
	struct neighbour *neigh = NULL;
	struct dst_entry *dst = skb_dst(skb);

	if (hw_path->flags & HNAT_PATH_PPPOE) {
		memcpy(eth_hdr(skb)->h_source, hw_path->eth_src, ETH_ALEN);
		memcpy(eth_hdr(skb)->h_dest, hw_path->eth_dest, ETH_ALEN);
		return 0;
	}

	rcu_read_lock_bh();
	ipv6_nexthop =
		rt6_nexthop((struct rt6_info *)dst, &ipv6_hdr(skb)->daddr);
	neigh = __ipv6_neigh_lookup_noref(dst->dev, ipv6_nexthop);
	if (unlikely(!neigh)) {
		dev_notice(host->dev, "%s:No neigh (daddr=%pI6)\n", __func__,
			   &ipv6_hdr(skb)->daddr);
		rcu_read_unlock_bh();
		return -1;
	}

	/* why do we get all zero ethernet address ? */
	if (!is_valid_ether_addr(neigh->ha)) {
		rcu_read_unlock_bh();
		return -1;
	}

	memcpy(eth_hdr(skb)->h_dest, neigh->ha, ETH_ALEN);
	memcpy(eth_hdr(skb)->h_source, out->dev_addr, ETH_ALEN);

	rcu_read_unlock_bh();

	return 0;
}

static unsigned int hnat_ipv4_get_nexthop(struct sk_buff *skb,
					  const struct net_device *out,
					  struct hnat_hw_path *hw_path)
{
	u32 nexthop;
	struct neighbour *neigh;
	struct dst_entry *dst = skb_dst(skb);
	struct rtable *rt = (struct rtable *)dst;
	struct net_device *dev = (__force struct net_device *)out;

	if (hw_path->flags & HNAT_PATH_PPPOE) {
		memcpy(eth_hdr(skb)->h_source, hw_path->eth_src, ETH_ALEN);
		memcpy(eth_hdr(skb)->h_dest, hw_path->eth_dest, ETH_ALEN);
		return 0;
	}

	rcu_read_lock_bh();
	nexthop = (__force u32)rt_nexthop(rt, ip_hdr(skb)->daddr);
	neigh = __ipv4_neigh_lookup_noref(dev, nexthop);
	if (unlikely(!neigh)) {
		dev_notice(host->dev, "%s:No neigh (daddr=%pI4)\n", __func__,
			   &ip_hdr(skb)->daddr);
		rcu_read_unlock_bh();
		return -1;
	}

	/* why do we get all zero ethernet address ? */
	if (!is_valid_ether_addr(neigh->ha)) {
		rcu_read_unlock_bh();
		return -1;
	}

	memcpy(eth_hdr(skb)->h_dest, neigh->ha, ETH_ALEN);
	memcpy(eth_hdr(skb)->h_source, out->dev_addr, ETH_ALEN);

	rcu_read_unlock_bh();

	return 0;
}

static u16 ppe_get_chkbase(struct iphdr *iph)
{
	u16 org_chksum = ntohs(iph->check);
	u16 org_tot_len = ntohs(iph->tot_len);
	u16 org_id = ntohs(iph->id);
	u16 chksum_tmp, tot_len_tmp, id_tmp;
	u32 tmp = 0;
	u16 chksum_base = 0;

	chksum_tmp = ~(org_chksum);
	tot_len_tmp = ~(org_tot_len);
	id_tmp = ~(org_id);
	tmp = chksum_tmp + tot_len_tmp + id_tmp;
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	tmp = ((tmp >> 16) & 0x7) + (tmp & 0xFFFF);
	chksum_base = tmp & 0xFFFF;

	return chksum_base;
}

struct foe_entry ppe_fill_L2_info(struct sk_buff *skb, struct foe_entry entry,
				  struct hnat_hw_path *hw_path)
{
	struct ethhdr *eth;

	eth = eth_hdr(skb);
	switch (entry.bfib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		entry.ipv4_hnapt.dmac_hi = swab32(*((u32 *)eth->h_dest));
		entry.ipv4_hnapt.dmac_lo = swab16(*((u16 *)&eth->h_dest[4]));
		entry.ipv4_hnapt.smac_hi = swab32(*((u32 *)eth->h_source));
		entry.ipv4_hnapt.smac_lo = swab16(*((u16 *)&eth->h_source[4]));
		entry.ipv4_hnapt.pppoe_id = hw_path->pppoe_sid;
		break;
	case IPV4_DSLITE:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
		entry.ipv6_5t_route.dmac_hi = swab32(*((u32 *)eth->h_dest));
		entry.ipv6_5t_route.dmac_lo = swab16(*((u16 *)&eth->h_dest[4]));
		entry.ipv6_5t_route.smac_hi = swab32(*((u32 *)eth->h_source));
		entry.ipv6_5t_route.smac_lo =
			swab16(*((u16 *)&eth->h_source[4]));
		entry.ipv6_5t_route.pppoe_id = hw_path->pppoe_sid;
		break;
	}
	return entry;
}

struct foe_entry ppe_fill_info_blk(struct sk_buff *skb, struct foe_entry entry,
				   struct hnat_hw_path *hw_path)
{
	struct ethhdr *eth;

	eth = eth_hdr(skb);
	entry.bfib1.psn = (hw_path->flags & HNAT_PATH_PPPOE) ? 1 : 0;
	entry.bfib1.vlan_layer = (hw_path->flags & HNAT_PATH_VLAN) ? 1 : 0;
	entry.bfib1.vpm = (hw_path->flags & HNAT_PATH_VLAN) ? 1 : 0;
	entry.bfib1.time_stamp = readl((host->fe_base + 0x0010)) & (0xFFFF);
	entry.bfib1.ttl = 1;
	entry.bfib1.cah = 1;
	entry.bfib1.ka = 1;
	switch (entry.bfib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		if (is_multicast_ether_addr(&eth->h_dest[0]))
			entry.ipv4_hnapt.iblk2.mcast = 1;
		else
			entry.ipv4_hnapt.iblk2.mcast = 0;

		entry.ipv4_hnapt.iblk2.port_ag = 0x3f;
		break;
	case IPV4_DSLITE:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
		if (is_multicast_ether_addr(&eth->h_dest[0]))
			entry.ipv6_5t_route.iblk2.mcast = 1;
		else
			entry.ipv6_5t_route.iblk2.mcast = 0;

		entry.ipv6_5t_route.iblk2.port_ag = 0x3f;
		break;
	}
	return entry;
}

static unsigned int skb_to_hnat_info(struct sk_buff *skb,
				     const struct net_device *dev,
				     struct foe_entry *foe,
				     struct hnat_hw_path *hw_path)
{
	struct foe_entry entry = { 0 };
	int whnat = IS_WHNAT(dev);
	struct ethhdr *eth;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	struct tcpudphdr _ports;
	const struct tcpudphdr *pptr;
	u32 gmac = NR_DISCARD;
	int udp = 0;
	u32 qid = 0;

	eth = eth_hdr(skb);
	if (is_multicast_ether_addr(eth->h_dest)) {
		/*do not bind multicast if PPE mcast not enable*/
		if (!host->pmcast)
			return 0;
	}
	entry.bfib1.pkt_type = foe->udib1.pkt_type; /* Get packte type state*/
	switch (ntohs(eth->h_proto)) {
	case ETH_P_IP:
		iph = ip_hdr(skb);
		switch (iph->protocol) {
		case IPPROTO_UDP:
			udp = 1;
		case IPPROTO_TCP:
			entry.ipv4_hnapt.etype = htons(ETH_P_IP);

#if defined(CONFIG_NET_DSA)
			if (IS_DSA_LAN(dev)) {
				entry.bfib1.vlan_layer = 1;
				entry.ipv4_hnapt.vlan1 = 0x00;

				/* etype is the destination port_map for special tag */
				if ((host->wan_dsa_port != NONE_DSA_PORT) &&
				    (host->wan_dsa_port == 0)) {
					/* wllll : wan at port0 , lan0 at port1 */
					entry.ipv4_hnapt.etype = htons(
						BIT((dev->name[3] - '0') + 1));
				} else {
					/* llllw : lan0 at port0 , wan/eth1(gphy) at port4 */
					entry.ipv4_hnapt.etype =
						htons(BIT(dev->name[3] - '0'));
				}

			} else if (IS_DSA_WAN(dev)) {
				entry.bfib1.vlan_layer = 1;
				entry.ipv4_hnapt.vlan1 = 0x00;

				entry.ipv4_hnapt.etype =
					htons(BIT(host->wan_dsa_port));
			}

			if (dev->priv_flags & IFF_802_1Q_VLAN) {
				struct vlan_dev_priv *vlan = vlan_dev_priv(dev);

				entry.ipv4_hnapt.etype = htons(ETH_P_8021Q);
				entry.bfib1.vlan_layer = 1;
				if (IS_LAN(dev))
					entry.ipv4_hnapt.vlan2 = vlan->vlan_id;
				else
					entry.ipv4_hnapt.vlan1 = vlan->vlan_id;
			}
#endif
			/* DS-Lite WAN->LAN */
			if (entry.ipv4_hnapt.bfib1.pkt_type == IPV4_DSLITE) {
				entry.ipv4_dslite.sip = foe->ipv4_dslite.sip;
				entry.ipv4_dslite.dip = foe->ipv4_dslite.dip;
				entry.ipv4_dslite.sport =
					foe->ipv4_dslite.sport;
				entry.ipv4_dslite.dport =
					foe->ipv4_dslite.dport;

				entry.ipv4_dslite.tunnel_sipv6_0 =
					foe->ipv4_dslite.tunnel_sipv6_0;
				entry.ipv4_dslite.tunnel_sipv6_1 =
					foe->ipv4_dslite.tunnel_sipv6_1;
				entry.ipv4_dslite.tunnel_sipv6_2 =
					foe->ipv4_dslite.tunnel_sipv6_2;
				entry.ipv4_dslite.tunnel_sipv6_3 =
					foe->ipv4_dslite.tunnel_sipv6_3;

				entry.ipv4_dslite.tunnel_dipv6_0 =
					foe->ipv4_dslite.tunnel_dipv6_0;
				entry.ipv4_dslite.tunnel_dipv6_1 =
					foe->ipv4_dslite.tunnel_dipv6_1;
				entry.ipv4_dslite.tunnel_dipv6_2 =
					foe->ipv4_dslite.tunnel_dipv6_2;
				entry.ipv4_dslite.tunnel_dipv6_3 =
					foe->ipv4_dslite.tunnel_dipv6_3;

				entry.ipv4_dslite.bfib1.rmt = 1;
				entry.ipv4_dslite.iblk2.dscp = iph->tos;
				if (host->data->per_flow_accounting)
					entry.ipv4_dslite.iblk2.mibf = 1;

			} else {
				entry.ipv4_hnapt.iblk2.dscp = iph->tos;
				if (host->data->per_flow_accounting)
					entry.ipv4_hnapt.iblk2.mibf = 1;

				entry.ipv4_hnapt.vlan1 = hw_path->vlan_id;

				entry.ipv4_hnapt.sip = foe->ipv4_hnapt.sip;
				entry.ipv4_hnapt.dip = foe->ipv4_hnapt.dip;
				entry.ipv4_hnapt.sport = foe->ipv4_hnapt.sport;
				entry.ipv4_hnapt.dport = foe->ipv4_hnapt.dport;

				entry.ipv4_hnapt.new_sip = ntohl(iph->saddr);
				entry.ipv4_hnapt.new_dip = ntohl(iph->daddr);
			}

			entry.ipv4_hnapt.bfib1.udp = udp;
			if (IS_IPV4_HNAPT(foe)) {
				pptr = skb_header_pointer(skb, iph->ihl * 4,
							  sizeof(_ports),
							  &_ports);
				entry.ipv4_hnapt.new_sport = ntohs(pptr->src);
				entry.ipv4_hnapt.new_dport = ntohs(pptr->dst);
			}

			break;

		default:
			return -1;
		}
		trace_printk(
			"[%s]skb->head=%p, skb->data=%p,ip_hdr=%p, skb->len=%d, skb->data_len=%d\n",
			__func__, skb->head, skb->data, iph, skb->len,
			skb->data_len);
		break;

	case ETH_P_IPV6:
		ip6h = ipv6_hdr(skb);
		switch (ip6h->nexthdr) {
		case NEXTHDR_UDP:
			udp = 1;
		case NEXTHDR_TCP: /* IPv6-5T or IPv6-3T */
			entry.ipv6_5t_route.etype = htons(ETH_P_IPV6);
			entry.ipv6_5t_route.vlan1 = hw_path->vlan_id;
			if (host->data->per_flow_accounting)
				entry.ipv6_5t_route.iblk2.mibf = 1;
			entry.ipv6_5t_route.bfib1.udp = udp;

			if (IS_IPV6_6RD(foe)) {
				entry.ipv6_5t_route.bfib1.rmt = 1;
				entry.ipv6_6rd.tunnel_sipv4 =
					foe->ipv6_6rd.tunnel_sipv4;
				entry.ipv6_6rd.tunnel_dipv4 =
					foe->ipv6_6rd.tunnel_dipv4;
			}

			entry.ipv6_3t_route.ipv6_sip0 =
				foe->ipv6_3t_route.ipv6_sip0;
			entry.ipv6_3t_route.ipv6_sip1 =
				foe->ipv6_3t_route.ipv6_sip1;
			entry.ipv6_3t_route.ipv6_sip2 =
				foe->ipv6_3t_route.ipv6_sip2;
			entry.ipv6_3t_route.ipv6_sip3 =
				foe->ipv6_3t_route.ipv6_sip3;

			entry.ipv6_3t_route.ipv6_dip0 =
				foe->ipv6_3t_route.ipv6_dip0;
			entry.ipv6_3t_route.ipv6_dip1 =
				foe->ipv6_3t_route.ipv6_dip1;
			entry.ipv6_3t_route.ipv6_dip2 =
				foe->ipv6_3t_route.ipv6_dip2;
			entry.ipv6_3t_route.ipv6_dip3 =
				foe->ipv6_3t_route.ipv6_dip3;

			if (IS_IPV6_5T_ROUTE(foe) || IS_IPV6_6RD(foe)) {
				entry.ipv6_5t_route.sport =
					foe->ipv6_5t_route.sport;
				entry.ipv6_5t_route.dport =
					foe->ipv6_5t_route.dport;
			}
			entry.ipv6_5t_route.iblk2.dscp =
				(ip6h->priority << 4 |
				 (ip6h->flow_lbl[0] >> 4));
			break;

		default:
			return -1;
		}

		trace_printk(
			"[%s]skb->head=%p, skb->data=%p,ipv6_hdr=%p, skb->len=%d, skb->data_len=%d\n",
			__func__, skb->head, skb->data, ip6h, skb->len,
			skb->data_len);
		break;

	default:
		ip6h = ipv6_hdr(skb);
		iph = ip_hdr(skb);
		switch (entry.bfib1.pkt_type) {
		case IPV6_6RD: /* 6RD LAN->WAN */
			entry.ipv6_6rd.ipv6_sip0 = foe->ipv6_6rd.ipv6_sip0;
			entry.ipv6_6rd.ipv6_sip1 = foe->ipv6_6rd.ipv6_sip1;
			entry.ipv6_6rd.ipv6_sip2 = foe->ipv6_6rd.ipv6_sip2;
			entry.ipv6_6rd.ipv6_sip3 = foe->ipv6_6rd.ipv6_sip3;

			entry.ipv6_6rd.ipv6_dip0 = foe->ipv6_6rd.ipv6_dip0;
			entry.ipv6_6rd.ipv6_dip1 = foe->ipv6_6rd.ipv6_dip1;
			entry.ipv6_6rd.ipv6_dip2 = foe->ipv6_6rd.ipv6_dip2;
			entry.ipv6_6rd.ipv6_dip3 = foe->ipv6_6rd.ipv6_dip3;

			entry.ipv6_6rd.sport = foe->ipv6_6rd.sport;
			entry.ipv6_6rd.dport = foe->ipv6_6rd.dport;
			entry.ipv6_6rd.tunnel_sipv4 = ntohl(iph->saddr);
			entry.ipv6_6rd.tunnel_dipv4 = ntohl(iph->daddr);
			entry.ipv6_6rd.hdr_chksum = ppe_get_chkbase(iph);
			entry.ipv6_6rd.flag = (ntohs(iph->frag_off) >> 13);
			entry.ipv6_6rd.ttl = iph->ttl;
			entry.ipv6_6rd.dscp = iph->tos;
			entry.ipv6_6rd.per_flow_6rd_id = 1;
			if (host->data->per_flow_accounting)
				entry.ipv6_6rd.iblk2.mibf = 1;
			break;
		case IPV4_DSLITE:
			/* DS-Lite LAN->WAN */
			if (ip6h->nexthdr == NEXTHDR_IPIP) {
				entry.ipv4_dslite.sip = foe->ipv4_dslite.sip;
				entry.ipv4_dslite.dip = foe->ipv4_dslite.dip;
				entry.ipv4_dslite.sport =
					foe->ipv4_dslite.sport;
				entry.ipv4_dslite.dport =
					foe->ipv4_dslite.dport;

				entry.ipv4_dslite.tunnel_sipv6_0 =
					ntohl(ip6h->saddr.s6_addr32[0]);
				entry.ipv4_dslite.tunnel_sipv6_1 =
					ntohl(ip6h->saddr.s6_addr32[1]);
				entry.ipv4_dslite.tunnel_sipv6_2 =
					ntohl(ip6h->saddr.s6_addr32[2]);
				entry.ipv4_dslite.tunnel_sipv6_3 =
					ntohl(ip6h->saddr.s6_addr32[3]);

				entry.ipv4_dslite.tunnel_dipv6_0 =
					ntohl(ip6h->daddr.s6_addr32[0]);
				entry.ipv4_dslite.tunnel_dipv6_1 =
					ntohl(ip6h->daddr.s6_addr32[1]);
				entry.ipv4_dslite.tunnel_dipv6_2 =
					ntohl(ip6h->daddr.s6_addr32[2]);
				entry.ipv4_dslite.tunnel_dipv6_3 =
					ntohl(ip6h->daddr.s6_addr32[3]);

				memcpy(entry.ipv4_dslite.flow_lbl,
				       ip6h->flow_lbl, sizeof(ip6h->flow_lbl));
				entry.ipv4_dslite.priority = ip6h->priority;
				entry.ipv4_dslite.hop_limit = ip6h->hop_limit;
				if (host->data->per_flow_accounting)
					entry.ipv4_dslite.iblk2.mibf = 1;
			}

			break;
		default:
			return -1;
		}
	}

	/* Fill Layer2 Info.*/
	entry = ppe_fill_L2_info(skb, entry, hw_path);

	/* Fill Info Blk*/
	entry = ppe_fill_info_blk(skb, entry, hw_path);

	if (host->gmac_num == 1) {
		gmac = NR_GMAC1_PORT;
	} else if (IS_LAN(dev)) {
		gmac = NR_GMAC1_PORT;
	} else if (IS_WAN(dev)) {
		gmac = NR_GMAC2_PORT;
	} else if (IS_EXT(dev) && (FROM_GE_LAN(skb) || FROM_GE_WAN(skb))) {
		trace_printk("learn of lan or wan(iif=%x) --> %s(ext)\n",
			     HNAT_SKB_CB(skb)->iif, dev->name);
		/* To CPU then stolen by pre-routing hant hook of LAN/WAN
		 * Current setting is PDMA RX.
		 */
		gmac = NR_PDMA_PORT;
		if (IS_IPV4_GRP(foe))
			entry.ipv4_hnapt.act_dp =
				get_index_from_devname(dev->name);
		else
			entry.ipv6_5t_route.act_dp =
				get_index_from_devname(dev->name);
	} else {
		dev_notice(host->dev, "Unknown case of dp, iif=%x --> %s\n",
			   HNAT_SKB_CB(skb)->iif, dev->name);

		return 0;
	}

	qid = skb->mark & (MTK_QDMA_TX_MASK);

	if (IS_IPV4_GRP(foe)) {
		entry.ipv4_hnapt.iblk2.dp = gmac;
		if (host->data->version == MTK_HNAT_V1)
			entry.ipv4_hnapt.iblk2.port_mg = 0x3f;
		else
			entry.ipv4_hnapt.iblk2.port_mg = 0;/*unused port_mg*/
#if defined(CONFIG_NET_MEDIATEK_HW_QOS)
		/* qid[5:0]= port_mg[1:0]+ qid[3:0] */
		entry.ipv4_hnapt.iblk2.qid = qid & 0xf;
		if (host->data->version != MTK_HNAT_V1)
			entry.ipv4_hnapt.iblk2.port_mg |= ((qid >> 4) & 0x3);
		if (IS_EXT(dev) && (FROM_GE_LAN(skb) || FROM_GE_WAN(skb))) {
			entry.ipv4_hnapt.etype = htons(0x5678);
			entry.ipv4_hnapt.vlan1 = skb_hnat_entry(skb);
			entry.bfib1.vlan_layer = 1;
		}
		if (FROM_EXT(skb))
			entry.ipv4_hnapt.iblk2.fqos = 0;
		else
			entry.ipv4_hnapt.iblk2.fqos = 1;
#else
		entry.ipv4_hnapt.iblk2.fqos = 0;
#endif
	} else {
		entry.ipv6_5t_route.iblk2.dp = gmac;
		if (host->data->version == MTK_HNAT_V1)
			entry.ipv6_5t_route.iblk2.port_mg = 0x3f;
		else
			entry.ipv6_5t_route.iblk2.port_mg = 0;/*unused port_mg*/
#if defined(CONFIG_NET_MEDIATEK_HW_QOS)
		/* qid[5:0]= port_mg[1:0]+ qid[3:0] */
		entry.ipv6_5t_route.iblk2.qid = qid & 0xf;
		if (host->data->version != MTK_HNAT_V1)
			entry.ipv6_5t_route.iblk2.port_mg |=
							((qid >> 4) & 0x3);
		if (IS_EXT(dev) && (FROM_GE_LAN(skb) || FROM_GE_WAN(skb))) {
			entry.ipv6_5t_route.etype = htons(0x5678);
			entry.ipv6_5t_route.vlan1 = skb_hnat_entry(skb);
			entry.bfib1.vlan_layer = 1;
		}
		if (FROM_EXT(skb))
			entry.ipv6_5t_route.iblk2.fqos = 0;
		else
			entry.ipv6_5t_route.iblk2.fqos = 1;
#else
		entry.ipv6_5t_route.iblk2.fqos = 0;
#endif
	}

	memcpy(foe, &entry, sizeof(entry));
	/*reset statistic for this entry*/
	if (host->data->per_flow_accounting)
		memset(&host->acct[skb_hnat_entry(skb)], 0,
		       sizeof(struct mib_entry));

	wmb();
	/* The INFO2.port_mg and 2nd VLAN ID fields of PPE entry are redefined
	 * by Wi-Fi whnat engine. These data and INFO2.dp will be updated and
	 * the entry is set to BIND state in mtk_sw_nat_hook_tx().
	 */
	if (!whnat)
		foe->bfib1.state = BIND;

	return 0;
}

int mtk_sw_nat_hook_tx(struct sk_buff *skb, int gmac_no)
{
	struct foe_entry *entry;
	struct ethhdr *eth;

	if (!IS_SPACE_AVAILABLE_HEAD(skb))
		return NF_ACCEPT;

	trace_printk(
		"[%s]entry=%x reason=%x gmac_no=%x wdmaid=%x rxid=%x wcid=%x bssid=%x\n",
		__func__, skb_hnat_entry(skb), skb_hnat_reason(skb), gmac_no,
		skb_hnat_wdma_id(skb), skb_hnat_bss_id(skb),
		skb_hnat_wc_id(skb), skb_hnat_rx_id(skb));

	if (!skb_hnat_is_hashed(skb))
		return NF_ACCEPT;

	entry = &host->foe_table_cpu[skb_hnat_entry(skb)];
	if (entry_hnat_is_bound(entry))
		return NF_ACCEPT;

	if (skb_hnat_reason(skb) != HIT_UNBIND_RATE_REACH ||
	    skb_hnat_alg(skb) != 0) {
		return NF_ACCEPT;
	}

	eth = eth_hdr(skb);
	if (is_multicast_ether_addr(eth->h_dest)) {
		/*not bind multicast if PPE mcast not enable*/
		if (!host->pmcast)
			return NF_ACCEPT;
	}

	/* Some mt_wifi virtual interfaces, such as apcli,
	 * will change the smac for specail purpose.
	 */
	switch (entry->bfib1.pkt_type) {
	case IPV4_HNAPT:
	case IPV4_HNAT:
		entry->ipv4_hnapt.smac_hi = swab32(*((u32 *)eth->h_source));
		entry->ipv4_hnapt.smac_lo = swab16(*((u16 *)&eth->h_source[4]));
		break;
	case IPV4_DSLITE:
	case IPV6_6RD:
	case IPV6_5T_ROUTE:
	case IPV6_3T_ROUTE:
		entry->ipv6_5t_route.smac_hi = swab32(*((u32 *)eth->h_source));
		entry->ipv6_5t_route.smac_lo = swab16(*((u16 *)&eth->h_source[4]));
		break;
	}

	/* MT7622 wifi hw_nat not support QoS */
	if (gmac_no == NR_WHNAT_WDMA_PORT) {
		entry->ipv4_hnapt.iblk2w.wdmaid =
			(skb_hnat_wdma_id(skb) & 0x01);
		entry->ipv4_hnapt.iblk2w.winfoi = 1;
		entry->ipv4_hnapt.winfo.bssid = skb_hnat_bss_id(skb);
		entry->ipv4_hnapt.winfo.wcid = skb_hnat_wc_id(skb);
		entry->ipv4_hnapt.winfo.rxid = skb_hnat_rx_id(skb);
	}
	entry->ipv4_hnapt.iblk2w.fqos = 0;
	entry->ipv4_hnapt.iblk2w.dp = gmac_no;
	entry->bfib1.state = BIND;

	return NF_ACCEPT;
}

void mtk_ppe_dev_register_hook(struct net_device *dev)
{
	int i;
	int index = 0, number = 0;
	struct extdev_entry *ext_entry;

	if (!strncmp(dev->name, "wds", 3))
		return;

	for (i = 1; i < MAX_IF_NUM; i++) {
		if (wifi_hook_if[i] == dev) {
			pr_info("%s : %s has been registered in wifi_hook_if table[%d]\n",
				__func__, dev->name, i);
			return;
		}
		if (!wifi_hook_if[i]) {
			index = get_index_from_devname(dev->name);
			if (index)
				goto add_wifi_hook_if;

			number = get_ext_device_number();
			if (number >= MAX_EXT_DEVS) {
				pr_info("%s : extdev array is full. %s is not registered\n",
					__func__, dev->name);
				return;
			}

			ext_entry = kzalloc(sizeof(*ext_entry), GFP_KERNEL);
			if (!ext_entry)
				return;

			strncpy(ext_entry->name, dev->name, IFNAMSIZ);
			dev_hold(dev);
			ext_entry->dev = dev;
			ext_if_add(ext_entry);

add_wifi_hook_if:
			dev_hold(dev);
			wifi_hook_if[i] = dev;

			break;
		}
	}
	pr_info("%s : ineterface %s register (%d)\n", __func__, dev->name, i);
}

void mtk_ppe_dev_unregister_hook(struct net_device *dev)
{
	int i;
	struct extdev_entry *ext_entry;

	for (i = 1; i < MAX_IF_NUM; i++) {
		if (wifi_hook_if[i] == dev) {
			wifi_hook_if[i] = NULL;
			dev_put(dev);

			break;
		}
	}

	for (i = 0; i < MAX_EXT_DEVS; i++) {
		ext_entry = ext_if[i];
		if (ext_entry && dev == ext_entry->dev) {
			ext_if_del(ext_entry);
			dev_put(dev);
			kfree(ext_entry);

			break;
		}
	}
	pr_info("%s : ineterface %s set null (%d)\n", __func__, dev->name, i);
}

static unsigned int mtk_hnat_accel_type(struct sk_buff *skb)
{
	struct dst_entry *dst;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;
	const struct nf_conn_help *help;

	/* Do not accelerate 1st round of xfrm flow, and 2nd round of xfrm flow
	 * is from local_out which is also filtered in sanity check.
	 */
	dst = skb_dst(skb);
	if (dst && dst_xfrm(dst))
		return 0;

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
		return 1;

	/* rcu_read_lock()ed by nf_hook_slow */
	help = nfct_help(ct);
	if (help && rcu_dereference(help->helper))
		return 0;

	return 1;
}

static unsigned int mtk_hnat_nf_post_routing(
	struct sk_buff *skb, const struct net_device *out,
	unsigned int (*fn)(struct sk_buff *, const struct net_device *,
			   struct hnat_hw_path *),
	const char *func)
{
	struct foe_entry *entry;
	struct hnat_hw_path hw_path = { .dev = out };

	if (unlikely(!IS_SPACE_AVAILABLE_HEAD(skb)))
		return 0;

	if (unlikely(!skb_hnat_is_hashed(skb)))
		return 0;

	/* Do not accelerate the alg or local_out traffic */
	if (skb_hnat_alg(skb))
		return 0;

	if (out->netdev_ops->ndo_hnat_check) {
		if (out->netdev_ops->ndo_hnat_check(&hw_path))
			return 0;
		out = hw_path.dev;
	}

	if (!IS_LAN(out) && !IS_WAN(out) && !IS_EXT(out))
		return 0;

	trace_printk("[%s] case hit, %x-->%s, reason=%x\n", __func__,
		     HNAT_SKB_CB(skb)->iif, out->name, skb_hnat_reason(skb));

	entry = &host->foe_table_cpu[skb_hnat_entry(skb)];

	switch (skb_hnat_reason(skb)) {
	case HIT_UNBIND_RATE_REACH:
		if (entry_hnat_is_bound(entry))
			break;

		if (fn && !mtk_hnat_accel_type(skb))
			break;

		if (fn && fn(skb, out, &hw_path))
			break;

		skb_to_hnat_info(skb, out, entry, &hw_path);
		break;
	case HIT_BIND_KEEPALIVE_DUP_OLD_HDR:
		if (fn && !mtk_hnat_accel_type(skb))
			break;

		if (entry_hnat_is_bound(entry)) {
			memset(skb_hnat_info(skb), 0, FOE_INFO_LEN);

			return -1;
		}
		break;
	case HIT_BIND_MULTICAST_TO_CPU:
	case HIT_BIND_MULTICAST_TO_GMAC_CPU:
		/*do not forward to gdma again,if ppe already done it*/
		if (IS_LAN(out) || IS_WAN(out))
			return -1;
		break;
	}

	return 0;
}

static unsigned int
mtk_hnat_ipv6_nf_local_out(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
	struct foe_entry *entry;
	struct ipv6hdr *ip6h;

	entry = &host->foe_table_cpu[skb_hnat_entry(skb)];

	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr == NEXTHDR_IPIP)
		entry->udib1.pkt_type = IPV4_DSLITE;

	return NF_ACCEPT;
}

static unsigned int
mtk_hnat_ipv6_nf_post_routing(void *priv, struct sk_buff *skb,
			      const struct nf_hook_state *state)
{
	post_routing_print(skb, state->in, state->out, __func__);

	if (!mtk_hnat_nf_post_routing(skb, state->out, hnat_ipv6_get_nexthop,
				      __func__))
		return NF_ACCEPT;

	trace_printk("%s:drop\n", __func__);
	return NF_DROP;
}

static unsigned int
mtk_hnat_ipv4_nf_post_routing(void *priv, struct sk_buff *skb,
			      const struct nf_hook_state *state)
{
	post_routing_print(skb, state->in, state->out, __func__);

	if (!mtk_hnat_nf_post_routing(skb, state->out, hnat_ipv4_get_nexthop,
				      __func__))
		return NF_ACCEPT;

	trace_printk("%s:drop\n", __func__);
	return NF_DROP;
}

static unsigned int
mtk_hnat_br_nf_post_routing(void *priv, struct sk_buff *skb,
			    const struct nf_hook_state *state)
{
	post_routing_print(skb, state->in, state->out, __func__);

	if (!mtk_hnat_nf_post_routing(skb, state->out, 0, __func__))
		return NF_ACCEPT;

	trace_printk("%s:drop\n", __func__);
	return NF_DROP;
}

static unsigned int
mtk_hnat_ipv4_nf_local_out(void *priv, struct sk_buff *skb,
			   const struct nf_hook_state *state)
{
	struct sk_buff *new_skb;
	struct foe_entry *entry;
	struct iphdr *iph;

	entry = &host->foe_table_cpu[skb_hnat_entry(skb)];

	if (unlikely(skb_headroom(skb) < FOE_INFO_LEN)) {
		new_skb = skb_realloc_headroom(skb, FOE_INFO_LEN);
		if (!new_skb) {
			dev_info(host->dev, "%s:drop\n", __func__);
			return NF_DROP;
		}
		dev_kfree_skb(skb);
		skb = new_skb;
	}

	/* Make the flow from local not be bound. */
	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_IPV6) {
		entry->udib1.pkt_type = IPV6_6RD;
		skb_hnat_alg(skb) = 0;
	} else {
		skb_hnat_alg(skb) = 1;
	}

	return NF_ACCEPT;
}

static unsigned int mtk_hnat_br_nf_forward(void *priv,
					   struct sk_buff *skb,
					   const struct nf_hook_state *state)
{
	if (unlikely(IS_EXT(state->in) && IS_EXT(state->out)))
		skb_hnat_alg(skb) = 1;

	return NF_ACCEPT;
}

static struct nf_hook_ops mtk_hnat_nf_ops[] __read_mostly = {
	{
		.hook = mtk_hnat_ipv4_nf_pre_routing,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = mtk_hnat_ipv6_nf_post_routing,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_ipv6_nf_local_out,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_ipv4_nf_post_routing,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_ipv4_nf_local_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_LAST,
	},
	{
		.hook = mtk_hnat_br_nf_pre_routing,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_PRE_ROUTING,
		.priority = NF_BR_PRI_FIRST,
	},
	{
		.hook = mtk_hnat_br_nf_forward,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_FORWARD,
		.priority = NF_BR_PRI_LAST - 1,
	},
	{
		.hook = mtk_hnat_br_nf_post_routing,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_BR_POST_ROUTING,
		.priority = NF_BR_PRI_LAST - 1,
	},
};

int hnat_register_nf_hooks(void)
{
	return nf_register_hooks(mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
}

void hnat_unregister_nf_hooks(void)
{
	nf_unregister_hooks(mtk_hnat_nf_ops, ARRAY_SIZE(mtk_hnat_nf_ops));
}
