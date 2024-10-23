#ifndef NETLINK_H
#define NETLINK_H

#include "dependency.h"

// Netlink 消息结构体
struct NetlinkMessage {
    uint8_t command;       // 用于表示接收到的命令
    uint16_t data_len;     // 消息中的数据长度
    char data[];           // 可变长度的数据，用于传输规则信息
};

// Netlink 通信套接字
extern struct sock *nl_sk;

// Netlink 通信管理函数声明
void send_error_response(int error_code);

void add_rule_handler(void *data, u_int16_t data_len);
void del_rule_handler(void *data, u_int16_t data_len);
void list_rules_handler(void);
void save_rules_handler(const char *filepath);
void load_rules_handler(const char *filepath);
void query_conn_handler(void);
void clear_conn_handler(void);
void add_nat_rule_handler(void *data, u_int16_t data_len);
void del_nat_rule_handler(void *data, u_int16_t data_len);
void list_nat_rules_handler(void);
void flush_logs_handler(void);
void get_logs_handler(void);
void set_default_handler(void *data, u_int16_t data_len);

#endif // NETLINK_H
