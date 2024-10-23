#include "firewall.h"

static struct nf_hook_ops nfop_in={
	.hook = hook_main,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfop_out={
	.hook = hook_main,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops natop_in={
	.hook = hook_nat_in,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_NAT_DST
};

static struct nf_hook_ops natop_out={
	.hook = hook_nat_out,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_NAT_SRC
};

// 钩子函数的初始化
int hook_init(void) {
    nf_register_net_hook(&init_net, &nfop_in);
    nf_register_net_hook(&init_net, &nfop_out);
    nf_register_net_hook(&init_net, &natop_in);
    nf_register_net_hook(&init_net, &natop_out);
    return 0;
}

// 钩子函数的清理
void hook_exit(void) {
    nf_unregister_net_hook(&init_net, &nfop_in);
    nf_unregister_net_hook(&init_net, &nfop_out);
    nf_unregister_net_hook(&init_net, &natop_in);
    nf_unregister_net_hook(&init_net, &natop_out);
}

static int mod_init(void){
	printk("my firewall module loaded.\n");
	hook_init();
	netlink_init();
	conn_init();
	return 0;
}

static void mod_exit(void){
	printk("my firewall module exit.\n");
	hook_exit();
	netlink_exit();
	conn_exit();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("wyywwi");
module_init(mod_init);
module_exit(mod_exit);
