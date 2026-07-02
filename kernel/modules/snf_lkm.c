#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <net/netns/generic.h>

#define HTTP_PORT 80

static unsigned int lkm_net_id;

/*
 * This structure stores the Netfilter hook for each network namespace.
 * The original kernel-playground style uses per-network-namespace data,
 * so we keep the same structure.
 */
struct lkm_netns_data {
        struct nf_hook_ops nf_hops;
};

/*
 * This function is called by Netfilter whenever an IPv4 packet reaches
 * the selected hook point.
 *
 * Our goal:
 * 1. Check that the packet exists.
 * 2. Check that it is an IPv4 packet.
 * 3. Check that it is a TCP packet.
 * 4. Check that the TCP destination port is 80.
 * 5. Log the source IP address.
 * 6. Accept the packet.
 */
static unsigned int nf_callback(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
        struct iphdr *iph;
        struct tcphdr *tcph;
        unsigned int ip_hdr_len;

        /*
         * If the socket buffer is empty, we do nothing.
         * The packet is accepted.
         */
        if (!skb)
                return NF_ACCEPT;

        /*
         * Make sure the packet contains at least a full IPv4 header.
         * If not, accept it without processing.
         */
        if (!pskb_may_pull(skb, sizeof(struct iphdr)))
                return NF_ACCEPT;

        iph = ip_hdr(skb);

        /*
         * We only handle IPv4 packets.
         */
        if (iph->version != 4)
                return NF_ACCEPT;

        /*
         * We only handle TCP packets because HTTP normally uses TCP.
         */
        if (iph->protocol != IPPROTO_TCP)
                return NF_ACCEPT;

        /*
         * IPv4 headers can have variable length.
         * ihl gives the header length in 32-bit words, so we multiply by 4.
         */
        ip_hdr_len = iph->ihl * 4;

        /*
         * If the IPv4 header length is invalid, accept the packet.
         */
        if (ip_hdr_len < sizeof(struct iphdr))
                return NF_ACCEPT;

        /*
         * Make sure the packet contains both the IPv4 header and TCP header.
         */
        if (!pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr)))
                return NF_ACCEPT;

        /*
         * Re-read the IP header after pskb_may_pull(), because the skb data
         * may have been adjusted.
         */
        iph = ip_hdr(skb);

        /*
         * The TCP header starts immediately after the IPv4 header.
         */
        tcph = (struct tcphdr *)((unsigned char *)iph + ip_hdr_len);

        /*
         * Basic requirement:
         * Detect HTTP traffic by checking destination TCP port 80.
         *
         * Intermediate requirement:
         * Log the source IP address to the kernel log.
         */
        if (tcph->dest == htons(HTTP_PORT)) {
                printk(KERN_INFO
                       "snf_lkm: HTTP packet detected: src=%pI4 dst=%pI4 sport=%u dport=%u\n",
                       &iph->saddr,
                       &iph->daddr,
                       ntohs(tcph->source),
                       ntohs(tcph->dest));
        }

        /*
         * This version does not block anything.
         * All packets are accepted.
         */
        return NF_ACCEPT;
}

/*
 * Netfilter hook configuration.
 *
 * NF_INET_PRE_ROUTING means the packet is inspected early,
 * before it is delivered to the local system.
 *
 * PF_INET means IPv4.
 */
static const struct nf_hook_ops lkm_nf_hook_ops_template = {
        .hook           = nf_callback,
        .hooknum        = NF_INET_PRE_ROUTING,
        .pf             = PF_INET,
        .priority       = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops *lkm_nf_hook_ops(struct net *net)
{
        struct lkm_netns_data *netns_data = net_generic(net, lkm_net_id);

        return &netns_data->nf_hops;
}

/*
 * This function runs when the module is registered for a network namespace.
 * It registers our Netfilter hook.
 */
static int __net_init netns_init(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);
        int rc;

        memcpy(ops, &lkm_nf_hook_ops_template, sizeof(*ops));

        rc = nf_register_net_hook(net, ops);
        if (rc) {
                printk(KERN_ERR "snf_lkm: cannot register netfilter hook\n");
                return rc;
        }

        printk(KERN_INFO "snf_lkm: IPv4 HTTP packet logger registered\n");
        return 0;
}

/*
 * This function runs when the network namespace is removed.
 * It unregisters the Netfilter hook.
 */
static void __net_exit netns_exit(struct net *net)
{
        struct nf_hook_ops *ops = lkm_nf_hook_ops(net);

        nf_unregister_net_hook(net, ops);

        printk(KERN_INFO "snf_lkm: netfilter hook unregistered\n");
}

/*
 * Per-network-namespace operations.
 */
static struct pernet_operations lkm_netns_ops = {
        .init = netns_init,
        .exit = netns_exit,
        .id = &lkm_net_id,
        .size = sizeof(struct lkm_netns_data),
};

/*
 * Module initialization function.
 * This runs when we load the module using insmod.
 */
static int __init lkm_init(void)
{
        int rc;

        rc = register_pernet_subsys(&lkm_netns_ops);
        if (rc) {
                printk(KERN_ERR "snf_lkm: cannot register pernet operations\n");
                return rc;
        }

        printk(KERN_INFO "snf_lkm: HTTP packet logger module loaded\n");
        return 0;
}

/*
 * Module cleanup function.
 * This runs when we remove the module using rmmod.
 */
static void __exit lkm_exit(void)
{
        unregister_pernet_subsys(&lkm_netns_ops);

        printk(KERN_INFO "snf_lkm: HTTP packet logger module unloaded\n");
}

module_init(lkm_init);
module_exit(lkm_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mayer / modified for M3 HTTP packet logging");
MODULE_DESCRIPTION("Linux Netfilter module for detecting IPv4 TCP HTTP packets and logging source IP addresses");
MODULE_VERSION("1.0.0");
