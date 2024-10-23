#include "firewall.h"

static spinlock_t hook_lock;  // 加入全局锁，用于hook函数

// 主钩子函数处理逻辑
unsigned int hook_main(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = ip_hdr(skb);
    struct tcphdr *tcp_header = NULL;
    struct ConnTrackHash *conn;
    conn_key_t key;
    
    // 加锁保护共享数据
    spin_lock(&hook_lock);

    // 提取五元组信息，生成连接键
    key.saddr = ntohl(ip_header->saddr);
    key.daddr = ntohl(ip_header->daddr);
    key.protocol = ip_header->protocol;

    // 处理TCP协议
    if (ip_header->protocol == IPPROTO_TCP) {
        tcp_header = tcp_hdr(skb);
        key.sport = ntohs(tcp_header->source);
        key.dport = ntohs(tcp_header->dest);

        // 查找现有连接
        conn = find_conn_in_table(key);
        if (conn) {
            // 更新连接状态
            if (!update_tcp_state(conn, tcp_header)) {
                // 如果包类型非法，丢弃数据包
                add_log_entry(LOG_TYPE_DROP, key.saddr, key.daddr, key.sport, key.dport, "Illegal TCP packet dropped");
                spin_unlock(&hook_lock);  // 解锁
                return NF_DROP;  // 丢弃包
            }
        }
        else {
            // 没有现存连接，检查是否为SYN包
            if (tcp_header->syn) {
                // 遍历规则表，匹配规则
                if (match_rules(ip_header, tcp_header)) {
                    conn = create_new_conn(key, tcp_header);
                    insert_conn_into_table(conn);
                    add_log_entry(LOG_TYPE_CONN_ESTABLISHED, key.saddr, key.daddr, key.sport, key.dport, "New TCP connection established");
                }
                else {
                    // 规则不允许，丢弃
                    add_log_entry(LOG_TYPE_DROP, key.saddr, key.daddr, key.sport, key.dport, "TCP packet dropped due to rule");
                    spin_unlock(&hook_lock);  // 解锁
                    return NF_DROP;
                }
            }
            else {
                // 不是SYN包，丢弃包
                add_log_entry(LOG_TYPE_DROP, key.saddr, key.daddr, key.sport, key.dport, "Non-SYN TCP packet dropped");
                spin_unlock(&hook_lock);  // 解锁
                return NF_DROP;
            }
        }
        // 如果通过了上述检查，接受该包
        update_conn_expires(conn);  // 更新连接的过期时间
        spin_unlock(&hook_lock);  // 解锁
        return NF_ACCEPT;
    }
    else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = udp_hdr(skb);
        key.sport = ntohs(udp_header->source);  // 提取源端口
        key.dport = ntohs(udp_header->dest);    // 提取目的端口

        // 查找现有连接（如果有连接跟踪）
        conn = find_conn_in_table(key);
        if (conn) {
            // 如果存在匹配的连接记录，放行数据包
            update_conn_expires(conn);  // 更新连接的过期时间
            spin_unlock(&hook_lock);  // 解锁
            return NF_ACCEPT;
        }
        // 匹配规则表
        if (match_rules(ip_header, udp_header)) {
            conn = create_new_conn(key, udp_header);
            insert_conn_into_table(conn);  // 插入连接表
            add_log_entry(LOG_TYPE_CONN_ESTABLISHED, key.saddr, key.daddr, key.sport, key.dport, "New UDP connection established");
            spin_unlock(&hook_lock);  // 解锁
            return NF_ACCEPT;  // 放行数据包
        } else {
            // 规则不允许，丢弃
            add_log_entry(LOG_TYPE_DROP, key.saddr, key.daddr, key.sport, key.dport, "UDP packet dropped due to rule");
            spin_unlock(&hook_lock);  // 解锁
            return NF_DROP;
        }
    }
    else if (ip_header->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp_header = (struct icmphdr *)skb_transport_header(skb);
        key.sport = 0;  // ICMP 不使用端口，因此这里的 sport 置为 0
        key.dport = 0;

        // 查找现有连接
        conn = find_conn_in_table(key);
        if (conn) {
            // 如果存在匹配的连接记录，放行数据包
            update_conn_expires(conn);  // 更新连接的过期时间
            spin_unlock(&hook_lock);  // 解锁
            return NF_ACCEPT;
        }

        // 匹配规则表
        if (match_rules(ip_header, icmp_header)) {
            conn = create_new_conn(key, icmp_header);
            insert_conn_into_table(conn);  // 插入连接表
            add_log_entry(LOG_TYPE_CONN_ESTABLISHED, key.saddr, key.daddr, key.sport, key.dport, "New ICMP connection established");
            spin_unlock(&hook_lock);  // 解锁
            return NF_ACCEPT;  // 放行数据包
        } else {
            // 规则不允许，丢弃数据包
            add_log_entry(LOG_TYPE_DROP, key.saddr, key.daddr, key.sport, key.dport, "ICMP packet dropped due to rule");
            spin_unlock(&hook_lock);  // 解锁
            return NF_DROP;
        }
    }
    spin_unlock(&hook_lock);  // 解锁
    return NF_ACCEPT;  // 默认接受
}

// NAT处理函数
unsigned int hook_nat_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = ip_hdr(skb);
    u_int32_t daddr = ntohl(ip_header->daddr);
    u_int32_t saddr = ntohl(ip_header->saddr);
    u_int16_t dport = 0;
    struct NATRecord *nat_record;

    spin_lock(&hook_lock);  // 加锁

    // 获取目的端口
    if (ip_header->protocol == IPPROTO_TCP) {
        dport = ntohs(tcp_hdr(skb)->dest);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        dport = ntohs(udp_hdr(skb)->dest);
    }

    // 查找 NAT 记录或规则
    nat_record = get_nat_record(daddr, dport, saddr, NAT_TYPE_DEST);
    if (nat_record == NULL) {
        spin_unlock(&hook_lock);  // 解锁
        return NF_ACCEPT;  // 如果没有找到 NAT 记录或规则，直接放行
    }

    // 应用 DNAT 转换
    apply_dnat(ip_header, skb, nat_record);

    // 记录 NAT 日志
    add_log_entry(LOG_TYPE_CONN_ESTABLISHED, daddr, nat_record->daddr, dport, nat_record->dport, "DNAT applied");

    spin_unlock(&hook_lock);  // 解锁
    return NF_ACCEPT;  // 放行数据包
}


unsigned int hook_nat_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header = ip_hdr(skb);
    u_int32_t saddr = ntohl(ip_header->saddr);
    u_int32_t daddr = ntohl(ip_header->daddr);
    u_int16_t sport = 0;
    struct NATRecord *nat_record;

    spin_lock(&hook_lock);  // 加锁

    // 获取源端口
    if (ip_header->protocol == IPPROTO_TCP) {
        sport = ntohs(tcp_hdr(skb)->source);
    } else if (ip_header->protocol == IPPROTO_UDP) {
        sport = ntohs(udp_hdr(skb)->source);
    }

    // 查找 NAT 记录或规则
    nat_record = get_nat_record(saddr, sport, daddr, NAT_TYPE_SRC);
    if (nat_record == NULL) {
        spin_unlock(&hook_lock);  // 解锁
        return NF_ACCEPT;  // 如果没有找到 NAT 记录或规则，直接放行
    }

    // 应用 SNAT 转换
    apply_snat(ip_header, skb, nat_record);

    // 记录 NAT 日志
    add_log_entry(LOG_TYPE_CONN_ESTABLISHED, saddr, nat_record->daddr, sport, nat_record->dport, "SNAT applied");

    spin_unlock(&hook_lock);  // 解锁
    return NF_ACCEPT;  // 放行数据包
}
