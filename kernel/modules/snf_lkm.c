#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>

static const char *classify_ipv4_destination(__be32 daddr)
{
	u32 dst = ntohl(daddr);
	u8 first_octet = (dst >> 24) & 0xff;

	if (first_octet >= 1 && first_octet <= 126)
		return "Class A";

	if (first_octet >= 128 && first_octet <= 191)
		return "Class B";

	if (first_octet >= 192 && first_octet <= 223)
		return "Class C";

	return "Other / Reserved";
}

static unsigned int nf_callback(void *priv,
				struct sk_buff *skb,
				const struct nf_hook_state *state)
{
	struct iphdr *iph;
	const char *dst_class;

	(void)priv;
	(void)state;

	if (!skb)
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);

	if (!iph)
		return NF_ACCEPT;

	if (iph->version != 4)
		return NF_ACCEPT;

	if (iph->ihl < 5)
		return NF_ACCEPT;

	dst_class = classify_ipv4_destination(iph->daddr);

	pr_info("M6 Basic: destination %pI4 classified as %s\n",
		&iph->daddr, dst_class);

	return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {
	.hook = nf_callback,
	.hooknum = NF_INET_LOCAL_OUT,
	.pf = NFPROTO_IPV4,
	.priority = NF_IP_PRI_FIRST,
};

static int __init m6_init(void)
{
	int ret;

	ret = nf_register_net_hook(&init_net, &nfho);
	if (ret) {
		pr_err("M6 Basic: failed to register Netfilter hook\n");
		return ret;
	}

	pr_info("M6 Basic: Destination IP Classifier loaded\n");
	return 0;
}

static void __exit m6_exit(void)
{
	nf_unregister_net_hook(&init_net, &nfho);
	pr_info("M6 Basic: Destination IP Classifier unloaded\n");
}

module_init(m6_init);
module_exit(m6_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fakhriddin Shamuratov - matricola 0363580");
MODULE_DESCRIPTION("M6 Basic: IPv4 Destination IP Classifier using Netfilter");
MODULE_VERSION("1.0.0");
