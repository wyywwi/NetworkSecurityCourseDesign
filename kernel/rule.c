#include "firewall.h"

u_int8_t default_action = 1;  // 1 表示接受，0 表示丢弃

// 全局规则链表定义
static struct IPRule* rule_list_head = NULL;
static DEFINE_RWLOCK(rule_list_lock);  // 读写锁，用于保护规则链表
extern struct sock *nl_sk;  // 外部声明 Netlink 套接字

// 添加新的防火墙规则
int add_rule(struct IPRule* new_rule) {
    struct IPRule* rule;
    struct IPRule* new_entry;

    write_lock(&rule_list_lock);  // 加写锁

    // 检查是否已存在同名规则
    rule = rule_list_head;
    while (rule) {
        if (strncmp(rule->name, new_rule->name, sizeof(rule->name)) == 0) {
            write_unlock(&rule_list_lock);  // 解写锁
            printk(KERN_ERR "Firewall: Rule with name '%s' already exists\n", new_rule->name);
            return -EEXIST;
        }
        rule = rule->next;
    }

    // 检查端口范围有效性
    if (new_rule->sport_min > new_rule->sport_max || new_rule->dport_min > new_rule->dport_max) {
        write_unlock(&rule_list_lock);  // 解写锁
        printk(KERN_ERR "Firewall: Invalid port range for rule '%s'\n", new_rule->name);
        return -EINVAL;
    }

    // 分配内存并复制规则
    new_entry = kmalloc(sizeof(struct IPRule), GFP_KERNEL);
    if (!new_entry) {
        write_unlock(&rule_list_lock);  // 解写锁
        printk(KERN_ERR "Firewall: Memory allocation failed for new rule\n");
        return -ENOMEM;
    }
    memcpy(new_entry, new_rule, sizeof(struct IPRule));
    new_entry->next = rule_list_head;
    rule_list_head = new_entry;

    write_unlock(&rule_list_lock);  // 解写锁

    printk(KERN_INFO "Firewall: Added new rule '%s'\n", new_rule->name);
    add_log_entry(LOG_TYPE_ADMIN, new_entry->saddr, new_entry->daddr, new_entry->sport_min, new_entry->dport_min, "Rule added");
    return 0;
}

// 修改现有防火墙规则
int modify_rule(const char* rule_name, struct IPRule* new_rule) {
    struct IPRule* rule;

    write_lock(&rule_list_lock);  // 加写锁

    // 查找要修改的规则
    rule = rule_list_head;
    while (rule) {
        if (strncmp(rule->name, rule_name, sizeof(rule->name)) == 0) {
            // 检查端口范围有效性
            if (new_rule->sport_min > new_rule->sport_max || new_rule->dport_min > new_rule->dport_max) {
                write_unlock(&rule_list_lock);  // 解写锁
                printk(KERN_ERR "Firewall: Invalid port range for rule '%s'\n", rule_name);
                return -EINVAL;
            }
            // 修改规则内容
            memcpy(rule, new_rule, sizeof(struct IPRule));
            write_unlock(&rule_list_lock);  // 解写锁
            printk(KERN_INFO "Firewall: Modified rule '%s'\n", rule_name);
            add_log_entry(LOG_TYPE_ADMIN, rule->saddr, rule->daddr, rule->sport_min, rule->dport_min, "Rule modified");
            return 0;
        }
        rule = rule->next;
    }

    write_unlock(&rule_list_lock);  // 解写锁
    printk(KERN_ERR "Firewall: Rule with name '%s' not found\n", rule_name);
    return -ENOENT;
}

// 删除防火墙规则
int del_rule(const char* rule_name) {
    struct IPRule* rule = rule_list_head;
    struct IPRule* prev = NULL;

    // 查找要删除的规则
    while (rule) {
        if (strncmp(rule->name, rule_name, sizeof(rule->name)) == 0) {
            if (prev) {
                prev->next = rule->next;
            } else {
                rule_list_head = rule->next;
            }
            kfree(rule);
            printk(KERN_INFO "Firewall: Deleted rule '%s'\n", rule_name);
            return 0;
        }
        prev = rule;
        rule = rule->next;
    }

    printk(KERN_ERR "Firewall: Rule with name '%s' not found\n", rule_name);
    return -ENOENT;
}

// 列出所有防火墙规则并通过 Netlink 返回
void list_rules(void) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = 4096;  // 初始消息大小为 4096 字节
    struct IPRule* rule;
    char *msg;
    int ret;

    read_lock(&rule_list_lock);  // 加读锁

    // 为 netlink 消息分配内存
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        read_unlock(&rule_list_lock);  // 解读锁
        printk(KERN_ERR "Firewall: Failed to allocate netlink message\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        read_unlock(&rule_list_lock);  // 解读锁
        printk(KERN_ERR "Firewall: Failed to put netlink message\n");
        return;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, msg_size);

    // 遍历规则链表，打包规则信息为 JSON 格式
    strncat(msg, "{\"rules\": [", msg_size - 1);
    rule = rule_list_head;
    while (rule) {
        ret = snprintf(msg + strlen(msg), msg_size - strlen(msg),
                 "{\"name\": \"%s\", \"saddr\": %u, \"smask\": %u, \"daddr\": %u, \"dmask\": %u, \"sport_min\": %u, \"sport_max\": %u, \"dport_min\": %u, \"dport_max\": %u, \"protocol\": %u, \"action\": %u}",
                 rule->name, rule->saddr, rule->smask, rule->daddr, rule->dmask, rule->sport_min, rule->sport_max, rule->dport_min, rule->dport_max, rule->protocol, rule->action);

        // 检查写入的长度是否超过剩余大小
        if (ret >= (msg_size - strlen(msg))) {
            // 如果缓冲区大小不够，则动态扩展缓冲区
            msg_size *= 2;
            skb = nlmsg_new(msg_size, GFP_KERNEL);
            if (!skb) {
                read_unlock(&rule_list_lock);  // 解读锁
                printk(KERN_ERR "Firewall: Failed to allocate larger netlink message\n");
                return;
            }
            nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
            if (!nlh) {
                kfree_skb(skb);
                read_unlock(&rule_list_lock);  // 解读锁
                printk(KERN_ERR "Firewall: Failed to put netlink message\n");
                return;
            }
            msg = nlmsg_data(nlh);
            memset(msg, 0, msg_size);
            rule = rule_list_head;  // 重新开始遍历规则链表
            continue;
        }

        rule = rule->next;
        if (rule) {
            strncat(msg, ",", msg_size - strlen(msg) - 1);  // 添加逗号分隔多个规则
        }
    }
    strncat(msg, "]}", msg_size - strlen(msg) - 1);

    read_unlock(&rule_list_lock);  // 解读锁

    // 发送 netlink 消息
    NETLINK_CB(skb).dst_group = 0;  // 非多播
    nlmsg_unicast(nl_sk, skb, 0);
}

// 保存规则到文件
int save_rules(const char* filepath) {
    struct file *file;
    loff_t pos = 0;
    struct IPRule* rule;
    char buf[256];

    // 检查文件路径是否有效
    if (!filepath || strlen(filepath) == 0) {
        printk(KERN_ERR "Firewall: Invalid file path for saving rules\n");
        return -EINVAL;
    }

    // 打开文件
    file = filp_open(filepath, O_WRONLY | O_CREAT, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Firewall: Failed to open file for saving rules\n");
        return PTR_ERR(file);
    }

    // 加读锁，防止其他线程同时修改规则
    read_lock(&rule_list_lock);

    // 遍历规则链表并写入文件
    rule = rule_list_head;
    while (rule) {
        snprintf(buf, sizeof(buf), "%s %u %u %u %u %u %u %u %u %u %u\n", rule->name, rule->saddr, rule->smask, rule->daddr, rule->dmask, rule->sport_min, rule->sport_max, rule->dport_min, rule->dport_max, rule->protocol, rule->action);
        kernel_write(file, buf, strlen(buf), &pos);
        rule = rule->next;
    }

    read_unlock(&rule_list_lock);
    filp_close(file, NULL);
    printk(KERN_INFO "Firewall: Rules saved successfully\n");
    return 0;
}

// 从文件加载规则
int load_rules(const char* filepath) {
    struct file *file;
    loff_t pos = 0;
    char buf[256];
    struct IPRule rule;
    int bytes_read;
    char name[32];
    u_int32_t saddr, smask, daddr, dmask;
    u_int16_t sport_min, sport_max, dport_min, dport_max;
    u_int8_t protocol, action;

    // 检查文件路径是否有效
    if (!filepath || strlen(filepath) == 0) {
        printk(KERN_ERR "Firewall: Invalid file path for loading rules\n");
        return -EINVAL;
    }

    // 打开文件
    file = filp_open(filepath, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Firewall: Failed to open file for loading rules\n");
        return PTR_ERR(file);
    }

    // 加写锁，防止其他线程同时读取或修改规则
    write_lock(&rule_list_lock);

    // 逐行读取文件内容并解析规则
    while ((bytes_read = kernel_read(file, buf, sizeof(buf) - 1, &pos)) > 0) {
        buf[bytes_read] = '\0';  // 确保字符串以 null 终止
        if (sscanf(buf, "%31s %u %u %u %u %hu %hu %hu %hu %hhu %hhu", name, &saddr, &smask, &daddr, &dmask, &sport_min, &sport_max, &dport_min, &dport_max, &protocol, &action) == 11) {
            // 检查解析内容的有效性
            if (sport_min > sport_max || dport_min > dport_max || (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP && protocol != IPPROTO_ICMP)) {
                printk(KERN_ERR "Firewall: Invalid rule data in file\n");
                continue;
            }
            strncpy(rule.name, name, sizeof(rule.name));
            rule.saddr = saddr;
            rule.smask = smask;
            rule.daddr = daddr;
            rule.dmask = dmask;
            rule.sport_min = sport_min;
            rule.sport_max = sport_max;
            rule.dport_min = dport_min;
            rule.dport_max = dport_max;
            rule.protocol = protocol;
            rule.action = action;
            add_rule(&rule);
        } else {
            printk(KERN_ERR "Firewall: Failed to parse rule from file\n");
        }
    }

    write_unlock(&rule_list_lock);
    filp_close(file, NULL);

    printk(KERN_INFO "Firewall: Rules loaded successfully\n");
    return 0;
}

// 匹配规则
int match_rules(struct iphdr* ip_header, void* transport_header) {
    struct IPRule* rule = rule_list_head;
    u_int16_t sport = 0, dport = 0;
    u_int8_t protocol = ip_header->protocol;

    // 提取传输层端口信息
    if (protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)transport_header;
        sport = ntohs(tcp_header->source);
        dport = ntohs(tcp_header->dest);
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)transport_header;
        sport = ntohs(udp_header->source);
        dport = ntohs(udp_header->dest);
    }

    // 加读锁，防止其他线程同时修改规则
    read_lock(&rule_list_lock);

    // 遍历规则链表，匹配规则
    while (rule) {
        if ((rule->protocol == 0 || rule->protocol == protocol) &&
            (rule->saddr == 0 || (ip_header->saddr & rule->smask) == (rule->saddr & rule->smask)) &&
            (rule->daddr == 0 || (ip_header->daddr & rule->dmask) == (rule->daddr & rule->dmask)) &&
            (rule->sport_min <= sport && sport <= rule->sport_max) &&
            (rule->dport_min <= dport && dport <= rule->dport_max)) {
            return rule->action;  // 返回匹配的规则动作
        }
        rule = rule->next;
    }

    read_unlock(&rule_list_lock);

    // 返回默认动作
    return default_action;
}