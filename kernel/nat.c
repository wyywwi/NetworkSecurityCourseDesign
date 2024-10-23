#include "firewall.h"

// NAT 规则和记录链表的头指针
struct NATRule *nat_rules_head = NULL;
static struct NATRecord *nat_records_head = NULL;
static rwlock_t nat_rules_lock;    // NAT 规则表的读写锁
static rwlock_t nat_records_lock;  // NAT 记录表的读写锁

struct NATRecord* find_nat_record(u_int32_t addr, u_int16_t port, u_int8_t nat_type) {
    struct NATRecord *record;
    read_lock(&nat_records_lock);  // 加读锁
    record = nat_records_head;
    // 遍历 NATRecord 链表，查找匹配的 NAT 记录
    while (record != NULL) {
        if (record->saddr == addr && record->sport == port && record->nat_type == nat_type) {
            read_unlock(&nat_records_lock);  // 解读锁
            return record;  // 找到匹配的 NAT 记录
        }
        record = record->next;
    }
    read_unlock(&nat_records_lock);  // 解读锁
    return NULL;  // 没有找到匹配的 NAT 记录
}

struct NATRule* find_nat_rule(u_int32_t addr, u_int16_t port, u_int32_t naddr, u_int8_t nat_type) {
    struct NATRule *rule;
    read_lock(&nat_rules_lock);  // 加读锁
    rule = nat_rules_head;  // NATRule 链表的头指针
    // 遍历 NATRule 链表，查找匹配的 NAT 规则
    while (rule != NULL) {
        if (rule->nat_type == nat_type &&
            (addr & rule->smask) == (rule->saddr & rule->smask) &&
            (naddr & rule->smask) != (rule->saddr & rule->smask) &&
            naddr != rule->daddr) {
            read_unlock(&nat_rules_lock);  // 解读锁
            return rule;  // 找到匹配的 NAT 规则
        }
        rule = rule->next;
    }
    read_unlock(&nat_rules_lock);  // 解读锁
    return NULL;  // 没有找到匹配的 NAT 规则
}

u_int16_t get_new_nat_port(struct NATRule *rule) {
    u_int16_t port;
    int is_port_used;
    struct NATRecord *cur_record;

    read_lock(&nat_records_lock);  // 加读锁
    // 遍历可用的端口范围，寻找未使用的端口
    for (port = rule->minport; port <= rule->maxport; port++) {
        is_port_used = 0;
        cur_record = nat_records_head;

        // 检查当前端口是否已被 NAT 记录占用
        while (cur_record != NULL) {
            if (cur_record->dport == port && cur_record->nat_type == rule->nat_type) {
                is_port_used = 1;
                break;
            }
            cur_record = cur_record->next;
        }

        // 进一步检查当前端口是否被其他进程占用
        if (!is_port_used) {
            struct socket *sock;
            struct sockaddr_in addr;
            int ret;

            // 创建一个套接字来检查端口是否被占用
            sock = (struct socket *)kmalloc(sizeof(struct socket), GFP_KERNEL);
            if (sock == NULL) {
                continue;  // 如果套接字创建失败，跳过当前端口
            }

            ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
            if (ret < 0) {
                kfree(sock);
                continue;  // 如果套接字创建失败，跳过当前端口
            }

            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = htonl(INADDR_ANY);
            addr.sin_port = htons(port);

            // 尝试绑定到指定端口
            ret = sock->ops->bind(sock, (struct sockaddr *)&addr, sizeof(addr));
            sock_release(sock);

            if (ret >= 0) {
                read_unlock(&nat_records_lock);  // 解读锁
                // 如果绑定成功，表示端口可用
                return port;
            }
        }
    }
    read_unlock(&nat_records_lock);  // 解读锁

    // 如果没有可用端口，返回 0 表示失败
    return 0;
}

// 添加NAT规则
int add_nat_rule(struct NATRule *new_rule) {
    if (new_rule->minport > new_rule->maxport) {
        return -ERR_INVALID_ARGS;  // 返回错误
    }

    write_lock(&nat_rules_lock);  // 加写锁
    new_rule->next = nat_rules_head;  // 插入到 NAT 规则链表头部
    nat_rules_head = new_rule;
    write_unlock(&nat_rules_lock);  // 解写锁

    printk(KERN_INFO "Firewall: Added NAT rule: saddr=%u, daddr=%u, minport=%u, maxport=%u\n",
           new_rule->saddr, new_rule->daddr, new_rule->minport, new_rule->maxport);
    return ERR_OK;
}

// 删除NAT规则
int del_nat_rule(const char *rule_name) {
    struct NATRule *rule = nat_rules_head;
    struct NATRule *prev = NULL;

    write_lock(&nat_rules_lock);  // 加写锁
    while (rule) {
        if (strncmp(rule->name, rule_name, 32) == 0) {
            if (prev) {
                prev->next = rule->next;
            } else {
                nat_rules_head = rule->next;
            }
            kfree(rule);
            write_unlock(&nat_rules_lock);  // 解写锁
            printk(KERN_INFO "Firewall: Deleted NAT rule: %s\n", rule_name);
            return ERR_OK;
        }
        prev = rule;
        rule = rule->next;
    }
    write_unlock(&nat_rules_lock);  // 解写锁

    printk(KERN_INFO "Firewall: NAT rule not found for deletion: %s\n", rule_name);
    return -ERR_RULE_NOT_FOUND;
}

// 创建NAT记录
struct NATRecord* create_new_nat_record(u_int32_t addr, u_int16_t port, struct NATRule* rule) {
    struct NATRecord *record = kmalloc(sizeof(struct NATRecord), GFP_KERNEL);
    if (record == NULL) {
        return NULL;  // 内存分配失败
    }

    // 填写 NATRecord 的信息
    record->saddr = addr;
    record->daddr = rule->daddr;
    record->sport = port;
    record->dport = get_new_nat_port(rule);  // 动态分配新端口
    record->nat_type = rule->nat_type;

    write_lock(&nat_records_lock);  // 加写锁
    record->next = nat_records_head;
    nat_records_head = record;  // 插入到 NATRecord 链表头
    write_unlock(&nat_records_lock);  // 解写锁

    // 记录日志
    add_log_entry(LOG_TYPE_NAT, addr, record->daddr, port, record->dport, "New NAT record created");

    return record;  // 返回新建的 NAT 记录
}

// 查找 NAT 记录（优先使用现有记录）
struct NATRecord* get_nat_record(u_int32_t addr, u_int16_t port, u_int32_t naddr, u_int8_t nat_type) {
    // 1. 查找 NAT 记录
    struct NATRecord *nat_record = find_nat_record(addr, port, nat_type);
    if (nat_record) {
        return nat_record;  // 如果找到现有 NAT 记录，直接返回
    }
    // 2. 如果没有找到 NAT 记录，查找 NAT 规则
    struct NATRule *nat_rule = find_nat_rule(addr, port, naddr, nat_type);
    if (nat_rule == NULL) {
        return NULL;  // 没有找到 NAT 规则
    }
    // 3. 根据 NAT 规则新建 NAT 记录
    return create_new_nat_record(addr, port, nat_rule);
}

// 重新计算并更新 TCP 校验和
void update_tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header, struct sk_buff *skb) {
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(ntohs(ip_header->tot_len), ip_header->saddr, 
                                     ip_header->daddr, csum_partial(tcp_header, skb->len, 0));
}

// 重新计算并更新 UDP 校验和
void update_udp_checksum(struct iphdr *ip_header, struct udphdr *udp_header, struct sk_buff *skb) {
    udp_header->check = 0;
    udp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                          skb->len - ip_hdrlen(skb), IPPROTO_UDP,
                                          csum_partial(udp_header, skb->len, 0));
}

// 重新计算并更新 IP 校验和
void update_ip_checksum(struct iphdr *ip_header) {
    ip_header->check = 0;
    ip_header->check = ip_fast_csum((unsigned char *)ip_header, ip_header->ihl);
}

// 根据 NAT 记录转换目的地址和端口（DNAT）
void apply_dnat(struct iphdr *ip_header, struct sk_buff *skb, struct NATRecord *nat_record) {
    ip_header->daddr = htonl(nat_record->daddr);  // 转换目的地址
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = tcp_hdr(skb);
        tcp_header->dest = htons(nat_record->dport);  // 转换目的端口
        update_tcp_checksum(ip_header, tcp_header, skb);  // 更新 TCP 校验和
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = udp_hdr(skb);
        udp_header->dest = htons(nat_record->dport);  // 转换目的端口
        update_udp_checksum(ip_header, udp_header, skb);  // 更新 UDP 校验和
    }
    update_ip_checksum(ip_header);  // 更新 IP 校验和

    // 记录日志
    add_log_entry(LOG_TYPE_NAT, ntohl(ip_header->saddr), nat_record->daddr, 0, nat_record->dport, "DNAT applied");
}

// 根据 NAT 记录转换源地址和端口（SNAT）
void apply_snat(struct iphdr *ip_header, struct sk_buff *skb, struct NATRecord *nat_record) {
    ip_header->saddr = htonl(nat_record->daddr);  // 转换源地址
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = tcp_hdr(skb);
        tcp_header->source = htons(nat_record->dport);  // 转换源端口
        update_tcp_checksum(ip_header, tcp_header, skb);  // 更新 TCP 校验和
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = udp_hdr(skb);
        udp_header->source = htons(nat_record->dport);  // 转换源端口
        update_udp_checksum(ip_header, udp_header, skb);  // 更新 UDP 校验和
    }
    update_ip_checksum(ip_header);  // 更新 IP 校验和

    // 记录日志
    add_log_entry(LOG_TYPE_NAT, nat_record->daddr, ntohl(ip_header->daddr), nat_record->dport, 0, "SNAT applied");
}

// 初始化 NAT 模块
void nat_init(void) {
    rwlock_init(&nat_rules_lock);
    rwlock_init(&nat_records_lock);  // 初始化 NAT 记录表的读写锁
    add_log_entry(LOG_TYPE_ADMIN, 0, 0, 0, 0, "NAT module initialized");
}

// 退出 NAT 模块
void nat_exit(void) {
    struct NATRecord *record;
    write_lock(&nat_records_lock);  // 加写锁
    while (nat_records_head != NULL) {
        record = nat_records_head;
        nat_records_head = nat_records_head->next;
        kfree(record);
    }
    write_unlock(&nat_records_lock);  // 解写锁
    add_log_entry(LOG_TYPE_ADMIN, 0, 0, 0, 0, "NAT module exited");
}

// 将NAT规则打包发送
int send_all_nat_rules_via_netlink(void) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size;
    struct NATRule *rule;
    char *msg;
    int remaining_size;

    // 为 netlink 消息分配内存
    msg_size = 4096;  // 假设消息大小足够容纳所有 NAT 规则
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "Firewall: Failed to allocate netlink message\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to allocate netlink message");
        return -ERR_NO_MEMORY;  // 返回错误码
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "Firewall: Failed to put netlink message\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to put netlink message");
        return ERR_UNKNOWN;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, msg_size);
    remaining_size = msg_size;

    // 打包 NAT 规则为 JSON 格式
    strcat(msg, "{\"nat_rules\": [");
    read_lock(&nat_rules_lock);  // 加读锁
    rule = nat_rules_head;

    while (rule) {
        int len = snprintf(msg + strlen(msg), remaining_size,
                           "{\"name\": \"%s\", \"saddr\": %u, \"daddr\": %u, \"minport\": %u, \"maxport\": %u}",
                           rule->name, rule->saddr, rule->daddr, rule->minport, rule->maxport);
        if (len >= remaining_size) {
            read_unlock(&nat_rules_lock);  // 解读锁
            kfree_skb(skb);
            printk(KERN_ERR "Firewall: NAT rules message size exceeded\n");
            return ERR_UNKNOWN;  // 防止溢出
        }
        remaining_size -= len;
        rule = rule->next;
        if (rule) {
            strcat(msg, ",");
        }
    }
    strcat(msg, "]}");
    read_unlock(&nat_rules_lock);  // 解读锁

    // 发送 Netlink 消息
    NETLINK_CB(skb).dst_group = 0;  // 非多播
    nlmsg_unicast(nl_sk, skb, 0);

    return ERR_OK;  // 成功时返回 ERR_OK
}

int send_all_nat_records_via_netlink(void) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size;
    struct NATRecord *record;
    char *msg;
    int remaining_size;

    // 为 netlink 消息分配内存
    msg_size = 4096;  // 假设消息大小足够容纳所有 NAT 记录
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "Firewall: Failed to allocate netlink message\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to allocate netlink message");
        return -ERR_NO_MEMORY;  // 返回错误码
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "Firewall: Failed to put netlink message\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to put netlink message");
        return ERR_UNKNOWN;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, msg_size);
    remaining_size = msg_size;

    // 打包 NAT 记录为 JSON 格式
    strcat(msg, "{\"nat_records\": [");
    read_lock(&nat_records_lock);  // 加读锁
    record = nat_records_head;

    while (record) {
        int len = snprintf(msg + strlen(msg), remaining_size,
                           "{\"saddr\": %u, \"daddr\": %u, \"sport\": %u, \"dport\": %u, \"nat_type\": %u}",
                           record->saddr, record->daddr, record->sport, record->dport, record->nat_type);
        if (len >= remaining_size) {
            read_unlock(&nat_records_lock);  // 解读锁
            kfree_skb(skb);
            printk(KERN_ERR "Firewall: NAT records message size exceeded\n");
            return ERR_UNKNOWN;  // 防止溢出
        }
        remaining_size -= len;
        record = record->next;
        if (record) {
            strcat(msg, ",");
        }
    }
    strcat(msg, "]}");
    read_unlock(&nat_records_lock);  // 解读锁

    // 发送 Netlink 消息
    NETLINK_CB(skb).dst_group = 0;  // 非多播
    nlmsg_unicast(nl_sk, skb, 0);

    return ERR_OK;  // 成功时返回 ERR_OK
}
