#include "firewall.h"

// 全局哈希表定义
struct ConnTrackHash* conn_table[CONN_TABLE_SIZE];
static struct timer_list cleanup_timer;
static struct workqueue_struct *conn_cleanup_wq;
static spinlock_t conn_table_lock;  // 全局锁，用于保护conn_table
static void cleanup_work_handler(struct work_struct *work);

// 工作队列用于处理连接清理
static DECLARE_WORK(cleanup_work, cleanup_work_handler);

// 改良的哈希函数：计算连接键的哈希值
unsigned int hash_conn_key(conn_key_t key) {
    unsigned int hash = 0;
    hash ^= (key.saddr * 2654435761U);  // 使用大素数进行混合
    hash ^= (key.daddr * 2654435761U);
    hash ^= (key.sport * 31);
    hash ^= (key.dport * 31);
    hash ^= (key.protocol * 101);
    return hash % CONN_TABLE_SIZE;
}

// 查找现有连接
struct ConnTrackHash* find_conn_in_table(conn_key_t key) {
    unsigned int hash = hash_conn_key(key);
    struct ConnTrackHash* conn;

    spin_lock(&conn_table_lock);  // 加锁
    conn = conn_table[hash];

    // 线性遍历哈希桶链表
    while (conn) {
        if (conn->key.saddr == key.saddr && conn->key.daddr == key.daddr &&
            conn->key.sport == key.sport && conn->key.dport == key.dport &&
            conn->key.protocol == key.protocol) {
            spin_unlock(&conn_table_lock);  // 解锁
            return conn;  // 找到匹配的连接
        }
        conn = conn->next;
    }
    spin_unlock(&conn_table_lock);  // 解锁
    return NULL;  // 没有找到匹配的连接
}

// 插入连接到哈希表
void insert_conn_into_table(struct ConnTrackHash* new_conn) {
    unsigned int hash = hash_conn_key(new_conn->key);

    spin_lock(&conn_table_lock);  // 加锁
    new_conn->next = conn_table[hash];
    conn_table[hash] = new_conn;
    spin_unlock(&conn_table_lock);  // 解锁

    // 记录日志
    add_log_entry(LOG_TYPE_CONN_ESTABLISHED, new_conn->key.saddr, new_conn->key.daddr, new_conn->key.sport, new_conn->key.dport, "New connection inserted into table");
}

// 创建新的连接
struct ConnTrackHash* create_new_conn(conn_key_t key, void* header) {
    struct ConnTrackHash* new_conn;
    struct timespec64 current_time;

    // 为新的连接分配内存
    new_conn = kmalloc(sizeof(struct ConnTrackHash), GFP_ATOMIC);
    if (!new_conn) {
        printk(KERN_ERR "Firewall: Memory allocation for new connection failed\n");
        add_log_entry(LOG_TYPE_ERROR, key.saddr, key.daddr, key.sport, key.dport, "Memory allocation for new connection failed");
        return NULL;
    }

    // 填写连接键与状态
    new_conn->key = key;

    // 根据协议类型设置初始状态
    switch (key.protocol) {
        case IPPROTO_TCP:
            new_conn->state = TCP_STATE_SYN_SENT;  // TCP 连接初始状态为 SYN_SENT
            break;
        case IPPROTO_UDP:
            new_conn->state = UDP_STATE_NEW;  // UDP 连接初始状态为 NEW
            break;
        case IPPROTO_ICMP:
            new_conn->state = ICMP_STATE_ECHO_REQUEST;  // ICMP 连接初始状态为 ECHO_REQUEST
            break;
        default:
            new_conn->state = STATE_CLOSED;  // 其他协议初始为 CLOSED
            break;
    }

    // 获取当前时间并设置超时时间
    ktime_get_real_ts64(&current_time);
    new_conn->timestamp = current_time;
    new_conn->expires = jiffies + CLEANUP_INTERVAL;  // 连接的默认过期时间

    // 记录日志
    add_log_entry(LOG_TYPE_CONN_ESTABLISHED, key.saddr, key.daddr, key.sport, key.dport, "New connection created");

    return new_conn;
}

// 更新TCP状态
bool update_tcp_state(struct ConnTrackHash* conn, struct tcphdr* tcp_header) {
    bool valid = false;
    switch (conn->state) {
        case TCP_STATE_SYN_SENT:
            if (tcp_header->syn && tcp_header->ack) {
                conn->state = TCP_STATE_SYN_RECV;
                valid = true;  // 合法包
            }
            break;
        case TCP_STATE_SYN_RECV:
            if (tcp_header->ack && !tcp_header->syn) {
                conn->state = TCP_STATE_ESTABLISHED;
                valid = true;  // 合法包
            }
            break;
        case TCP_STATE_ESTABLISHED:
            if (tcp_header->fin) {
                conn->state = TCP_STATE_FIN_WAIT;
                valid = true;  // 合法包，处理连接关闭
            } else if (tcp_header->rst) {
                conn->state = STATE_CLOSED;
                valid = true;  // 合法包，处理连接重置
            } else if (tcp_header->syn) {
                valid = false;  // 非法包，不允许在 ESTABLISHED 状态下接收 SYN
            } else {
                valid = true;  // 正常的 ACK 包或数据包
            }
            break;
        case TCP_STATE_FIN_WAIT:
            if (tcp_header->ack) {
                conn->state = STATE_CLOSED;
                valid = true;  // 合法包
            } else if (tcp_header->rst) {
                conn->state = STATE_CLOSED;
                valid = true;  // 合法包
            }
            break;
        case STATE_CLOSED:
            if (tcp_header->syn && !tcp_header->ack) {
                conn->state = TCP_STATE_SYN_SENT;  // 更新为SYN_SENT，准备建立连接
                valid = true;  // 合法包，允许重建连接
            }
            valid = false;  // 非法包，连接已关闭
            break;
        default:
            valid = false; // 直接丢弃包
    }

    if (valid) {
        // 记录日志
        add_log_entry(LOG_TYPE_CONN_ESTABLISHED, conn->key.saddr, conn->key.daddr, conn->key.sport, conn->key.dport, "TCP state updated");
    }

    return valid;
}

// 更新连接的超时时间
void update_conn_expires(struct ConnTrackHash* conn) {
    spin_lock(&conn_table_lock);  // 加锁
    conn->expires = jiffies + CLEANUP_INTERVAL;
    spin_unlock(&conn_table_lock);  // 解锁

    // 记录日志
    add_log_entry(LOG_TYPE_INFO, conn->key.saddr, conn->key.daddr, conn->key.sport, conn->key.dport, "Connection expiry updated");
}

// 清理过期连接
void cleanup_conntrack(void) {
    unsigned int i;
    struct ConnTrackHash *conn, *prev, *tmp;
    unsigned long curr_time = jiffies;

    spin_lock(&conn_table_lock);  // 加锁
    for (i = 0; i < CONN_TABLE_SIZE; i++) {
        conn = conn_table[i];
        prev = NULL;

        while (conn) {
            if (time_after(curr_time, conn->expires)) {
                // 连接超时，清理连接
                if (prev) {
                    prev->next = conn->next;
                } else {
                    conn_table[i] = conn->next;
                }
                tmp = conn;
                conn = conn->next;

                // 记录日志
                add_log_entry(LOG_TYPE_CONN_TERMINATED, tmp->key.saddr, tmp->key.daddr, tmp->key.sport, tmp->key.dport, "Connection expired and removed");
                kfree(tmp);
            } else {
                prev = conn;
                conn = conn->next;
            }
        }
    }
    spin_unlock(&conn_table_lock);  // 解锁
}

// 连接清理工作处理函数
static void cleanup_work_handler(struct work_struct *work) {
    cleanup_conntrack();
    mod_timer(&cleanup_timer, jiffies + CLEANUP_INTERVAL);
}

// 定时器回调函数
void cleanup_timer_callback(struct timer_list *t) {
    queue_work(conn_cleanup_wq, &cleanup_work);
}

// 初始化连接定时清理
void conn_init(void) {
    spin_lock_init(&conn_table_lock);  // 初始化锁
    conn_cleanup_wq = create_singlethread_workqueue("conn_cleanup_wq");
    if (!conn_cleanup_wq) {
        printk(KERN_ERR "Firewall: Failed to create workqueue for connection cleanup\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to create workqueue for connection cleanup");
        return;
    }

    // 初始化定时器
    timer_setup(&cleanup_timer, (void *)cleanup_timer_callback, 0);
    mod_timer(&cleanup_timer, jiffies + CLEANUP_INTERVAL);
    printk(KERN_INFO "Firewall: Connection tracking module initialized\n");
    add_log_entry(LOG_TYPE_INFO, 0, 0, 0, 0, "Connection tracking module initialized");
}

// 退出连接定时清理
void conn_exit(void) {
    del_timer_sync(&cleanup_timer);
    if (conn_cleanup_wq) {
        flush_workqueue(conn_cleanup_wq);
        destroy_workqueue(conn_cleanup_wq);
    }
    printk(KERN_INFO "Firewall: Connection tracking module exited\n");
    add_log_entry(LOG_TYPE_INFO, 0, 0, 0, 0, "Connection tracking module exited");
}

// 更新连接的最后活动时间
void update_last_activity(struct ConnTrackHash* conn) {
    struct timespec64 current_time;
    ktime_get_real_ts64(&current_time);
    spin_lock(&conn_table_lock);  // 加锁
    conn->timestamp = current_time;
    spin_unlock(&conn_table_lock);  // 解锁

    // 记录日志
    add_log_entry(LOG_TYPE_INFO, conn->key.saddr, conn->key.daddr, conn->key.sport, conn->key.dport, "Last activity time updated");
}

// 删除指定连接
void delete_conn(struct ConnTrackHash* conn) {
    unsigned int hash = hash_conn_key(conn->key);
    struct ConnTrackHash *current_conn, *prev = NULL;

    spin_lock(&conn_table_lock);  // 加锁
    current_conn = conn_table[hash];
    while (current_conn) {
        if (current_conn == conn) {
            if (prev) {
                prev->next = current_conn->next;
            } else {
                conn_table[hash] = current_conn->next;
            }
            spin_unlock(&conn_table_lock);  // 解锁

            // 记录日志
            add_log_entry(LOG_TYPE_CONN_TERMINATED, conn->key.saddr, conn->key.daddr, conn->key.sport, conn->key.dport, "Connection deleted");
            kfree(current_conn);
            return;
        }
        prev = current_conn;
        current_conn = current_conn->next;
    }
    spin_unlock(&conn_table_lock);  // 解锁
}

// 清空连接
int clear_conn(void) {
    unsigned int i;
    struct ConnTrackHash *conn, *tmp;

    // 加锁，保护全局连接表的访问
    spin_lock(&conn_table_lock);

    // 遍历连接表并释放所有连接
    for (i = 0; i < CONN_TABLE_SIZE; i++) {
        conn = conn_table[i];
        while (conn) {
            tmp = conn;
            conn = conn->next;
            kfree(tmp);
        }
        conn_table[i] = NULL;
    }

    // 解锁
    spin_unlock(&conn_table_lock);

    // 记录日志和打印信息
    add_log_entry(LOG_TYPE_ADMIN, 0, 0, 0, 0, "Cleared all tracked connections");
    printk(KERN_INFO "Firewall: Cleared all tracked connections\n");
    return 0;
}

// 打包所有现有连接信息并通过 netlink 发送
void send_all_conn_info_via_netlink(void) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size;
    unsigned int i;
    struct ConnTrackHash *conn;
    char *msg;

    // 为 netlink 消息分配内存
    msg_size = 4096;  // 假设消息大小足够容纳所有连接信息
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "Firewall: Failed to allocate netlink message\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to allocate netlink message");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "Firewall: Failed to put netlink message\n");
        add_log_entry(LOG_TYPE_ERROR, 0, 0, 0, 0, "Failed to put netlink message");
        return;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, msg_size);

    // 遍历连接表，打包连接信息为 JSON 格式
    spin_lock(&conn_table_lock);  // 加锁
    strcat(msg, "{\"connections\": [");
    for (i = 0; i < CONN_TABLE_SIZE; i++) {
        conn = conn_table[i];
        while (conn) {
            snprintf(msg + strlen(msg), msg_size - strlen(msg),
                     "{\"saddr\": %u, \"daddr\": %u, \"sport\": %u, \"dport\": %u, \"protocol\": %u, \"state\": %u}",
                     conn->key.saddr, conn->key.daddr, conn->key.sport, conn->key.dport,
                     conn->key.protocol, conn->state);
            conn = conn->next;
            if (conn || i < CONN_TABLE_SIZE - 1) {
                strcat(msg, ",");  // 添加逗号分隔多个连接
            }
        }
    }
    strcat(msg, "]}");
    spin_unlock(&conn_table_lock);  // 解锁

    // 发送 netlink 消息
    NETLINK_CB(skb).dst_group = 0;  // 非多播
    nlmsg_unicast(nl_sk, skb, 0);
}
