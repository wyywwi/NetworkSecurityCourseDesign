#include "firewall.h"
#include "netlink.h"

#define NETLINK_USER 31

struct sock *nl_sk = NULL;
extern struct nf_hook_ops nfop_in, nfop_out, natop_in, natop_out;

// Netlink 消息接收回调函数
static void netlink_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh;
    struct NetlinkMessage *nl_msg;
    void *msg_data = NULL;

    if (!skb) {
        printk(KERN_ERR "Firewall: Received null skb in netlink_recv_msg\n");
        return;
    }

    // 提取 Netlink 消息头部
    nlh = (struct nlmsghdr *)skb->data;
    nl_msg = (struct NetlinkMessage *)nlmsg_data(nlh);
    msg_data = nl_msg->data;

    // 根据指令类型解析并执行相应操作
    switch (nl_msg->command) {
        case CMD_ADD_RULE:
            add_rule_handler(msg_data, nl_msg->data_len);
            break;
        case CMD_DEL_RULE:
            del_rule_handler(msg_data, nl_msg->data_len);
            break;
        case CMD_LIST_RULES:
            list_rules_handler();
            break;
        case CMD_SAVE_RULES:
            save_rules_handler((char *)msg_data);
            break;
        case CMD_LOAD_RULES:
            load_rules_handler((char *)msg_data);
            break;
        case CMD_QUERY_CONN:
            query_conn_handler();
            break;
        case CMD_CLEAR_CONN:
            clear_conn_handler();
            break;
        case CMD_ADD_NAT_RULE:
            add_nat_rule_handler(msg_data, nl_msg->data_len);
            break;
        case CMD_DEL_NAT_RULE:
            del_nat_rule_handler(msg_data, nl_msg->data_len);
            break;
        case CMD_LIST_NAT_RULES:
            list_nat_rules_handler();
            break;
        case CMD_LIST_NAT_RECORDS:
            list_nat_rules_handler();
            break;
        case CMD_FLUSH_LOGS:
            flush_logs_handler();
            break;
        case CMD_GET_LOGS:
            get_logs_handler();
            break;
        case CMD_SET_DEFAULT:
            set_default_handler(msg_data, nl_msg->data_len);
            break;
        default:
            printk(KERN_INFO "Firewall: Unknown command received: %d\n", nl_msg->command);
            send_error_response(ERR_INVALID_CMD);
            break;
    }
}

// 处理添加规则请求
void add_rule_handler(void *data, u_int16_t data_len) {
    if (data_len < sizeof(struct IPRule)) {
        send_error_response(ERR_INVALID_ARGS);
        return;
    }

    struct IPRule *rule = kmalloc(sizeof(struct IPRule), GFP_KERNEL);
    if (!rule) {
        send_error_response(ERR_NO_MEMORY);
        return;
    }
    memcpy(rule, data, sizeof(struct IPRule));

    // 调用 add_rule 函数添加规则
    int result = add_rule(rule);
    if (result == -EEXIST) {
        send_error_response(ERR_RULE_EXISTS);
    } else if (result == -EINVAL) {
        send_error_response(ERR_INVALID_ARGS);
    } else if (result == -ENOMEM) {
        send_error_response(ERR_NO_MEMORY);
    } else {
        send_error_response(ERR_OK);
    }

    // 释放规则内存，add_rule 中会复制数据，这里的临时 rule 结构体需要释放
    kfree(rule);
}

// 处理删除规则请求
void del_rule_handler(void *data, u_int16_t data_len) {
    if (data_len < sizeof(char) * 32) {
        send_error_response(ERR_INVALID_ARGS);
        return;
    }

    char *rule_name = (char *)data;
    int result = del_rule(rule_name);

    if (result == 0) {
        printk(KERN_INFO "Firewall: Deleted rule: %s\n", rule_name);
        add_log_entry(LOG_TYPE_ADMIN, 0, 0, 0, 0, "Rule deleted");
        send_error_response(ERR_OK);
    } else {
        printk(KERN_INFO "Firewall: Rule not found for deletion: %s\n", rule_name);
        send_error_response(ERR_RULE_NOT_FOUND);
    }
}

// 处理列出所有规则请求
void list_rules_handler(void) {
    list_rules();
    printk(KERN_INFO "Firewall: Listing all rules\n");
    send_error_response(ERR_OK);
}

// 处理保存规则请求
void save_rules_handler(const char *filepath) {
    if (!filepath || strlen(filepath) == 0) {  // 检查是否提供了路径
        filepath = "/etc/firewall_rules.conf";  // 使用默认路径
    }

    int result = save_rules(filepath);

    if (result == 0) {
        printk(KERN_INFO "Firewall: Rules saved successfully to %s\n", filepath);
        add_log_entry(LOG_TYPE_ADMIN, 0, 0, 0, 0, "Rules saved to file");
        send_error_response(ERR_OK);
    } else {
        printk(KERN_ERR "Firewall: Failed to save rules to %s\n", filepath);
        send_error_response(ERR_INVALID_ARGS);
    }
}

// 处理加载规则请求
void load_rules_handler(const char *filepath) {
    if (!filepath || strlen(filepath) == 0) {  // 检查是否提供了路径
        filepath = "/etc/firewall_rules.conf";  // 使用默认路径
    }

    int result = load_rules(filepath);

    if (result == 0) {
        printk(KERN_INFO "Firewall: Rules loaded successfully from %s\n", filepath);
        add_log_entry(LOG_TYPE_ADMIN, 0, 0, 0, 0, "Rules loaded from file");
        send_error_response(ERR_OK);
    } else {
        printk(KERN_ERR "Firewall: Failed to load rules from %s\n", filepath);
        send_error_response(ERR_INVALID_ARGS);
    }
}


// 处理查询连接状态请求
void query_conn_handler(void) {
    send_all_conn_info_via_netlink();
}

// 处理清理所有连接请求
void clear_conn_handler(void) {
    clear_conn();
    send_error_response(ERR_OK);
}

// 处理添加 NAT 规则请求
void add_nat_rule_handler(void *data, u_int16_t data_len) {
    if (data_len < sizeof(struct NATRule)) {
        send_error_response(ERR_INVALID_ARGS);
        return;
    }

    struct NATRule *new_rule = kmalloc(sizeof(struct NATRule), GFP_KERNEL);
    if (!new_rule) {
        send_error_response(ERR_NO_MEMORY);
        return;
    }

    memcpy(new_rule, data, sizeof(struct NATRule));
    int result = add_nat_rule(new_rule);

    if (result != ERR_OK) {
        kfree(new_rule);
        send_error_response(result);
        return;
    }

    send_error_response(ERR_OK);
}


// 处理删除 NAT 规则请求
void del_nat_rule_handler(void *data, u_int16_t data_len) {
    if (data_len < sizeof(char) * 32) {
        send_error_response(ERR_INVALID_ARGS);
        return;
    }

    char *rule_name = (char *)data;
    int result = del_nat_rule(rule_name);

    send_error_response(result);
}


// 处理列出 NAT 规则请求
void list_nat_rules_handler(void) {
    int result = send_all_nat_rules_via_netlink();
    if (result != ERR_OK) {
        send_error_response(result);  // 发送错误响应
    }
}

// 处理列出 NAT 记录请求
void list_nat_records_handler(void) {
    int result = send_all_nat_records_via_netlink();
    if (result != ERR_OK) {
        send_error_response(result);  // 发送错误响应
    }
}

// 处理清空日志请求
void flush_logs_handler(void) {
    flush_logs();
    printk(KERN_INFO "Firewall: Flushing all logs\n");
    send_error_response(ERR_OK);
}

// 处理获取日志请求
void get_logs_handler(void) {
    list_logs();
    printk(KERN_INFO "Firewall: Getting all logs\n");
    send_error_response(ERR_OK);
}

// 处理设置默认动作请求
void set_default_handler(void *data, u_int16_t data_len) {
    if (data_len < sizeof(u_int8_t)) {
        send_error_response(ERR_INVALID_ARGS);
        return;
    }

    u_int8_t action = *(u_int8_t *)data;
    default_action = action;
    printk(KERN_INFO "Firewall: Set default action to: %u\n", action);
    send_error_response(ERR_OK);
}

// 初始化 Netlink 套接字
int netlink_init(void) {
    struct netlink_kernel_cfg cfg = {
        .input = netlink_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ERR "Firewall: Failed to create Netlink socket\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "Firewall: Netlink socket created successfully\n");
    return 0;
}

// 清理 Netlink 套接字
void netlink_exit(void) {
    if (nl_sk) {
        netlink_kernel_release(nl_sk);
        printk(KERN_INFO "Firewall: Netlink socket released\n");
    }
}

// 发送错误响应
void send_error_response(int error_code) {
    struct sk_buff *skb_out;
    struct nlmsghdr *nlh;
    int msg_size = sizeof(int);
    int res;

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "Firewall: Failed to allocate new skb for error response\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; // 非多播

    *(int *)nlmsg_data(nlh) = error_code;

    res = nlmsg_unicast(nl_sk, skb_out, 0);
    if (res < 0) {
        printk(KERN_ERR "Firewall: Error while sending error response to user\n");
    }
}
