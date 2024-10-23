#ifndef FWCLI_H
#define FWCLI_H

// 标准库头文件
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <errno.h>

// Netlink 用户定义的协议号，必须与内核中定义的协议号一致
#define NETLINK_USER 31

// CLI命令枚举
enum CommandType {
    CMD_ADD_RULE,
    CMD_DEL_RULE,
    CMD_LIST_RULES,
    CMD_SAVE_RULES,
    CMD_LOAD_RULES,
    CMD_ADD_NAT_RULE,
    CMD_DEL_NAT_RULE,
    CMD_LIST_NAT_RULES,
    CMD_LIST_NAT_RECORDS,
    CMD_FLUSH_LOGS,
    CMD_GET_LOGS,
    CMD_QUERY_CONN,
    CMD_CLEAR_CONN,
    CMD_SET_DEFAULT,
    CMD_UNKNOWN
};

// Netlink 消息结构体，用于在用户空间与内核空间之间通信
struct NetlinkMessage {
    uint8_t command;       // 表示命令类型
    uint16_t data_len;     // 数据长度
    char data[];           // 可变长度数据，用于传递实际的规则或命令数据
};

// 防火墙规则结构体，用于在 CLI 和内核间传递规则信息
struct IPRule {
    char name[32];            // 规则名称
    u_int32_t saddr;          // 源IP地址
    u_int32_t smask;          // 源IP掩码
    u_int32_t daddr;          // 目的IP地址
    u_int32_t dmask;          // 目的IP掩码
    u_int16_t sport_min;      // 源端口范围（最小值）
    u_int16_t sport_max;      // 源端口范围（最大值）
    u_int16_t dport_min;      // 目的端口范围（最小值）
    u_int16_t dport_max;      // 目的端口范围（最大值）
    u_int8_t protocol;        // 协议类型 (TCP, UDP等)
    u_int8_t action;          // 动作：0表示丢弃，1表示接受
};

// NAT 规则结构体，用于在 CLI 和内核间传递 NAT 规则信息
struct NATRule {
    char name[32];            // 规则名称
    u_int32_t saddr;          // 外部IP地址
    u_int32_t smask;          // 外部IP掩码
    u_int32_t daddr;          // 内部IP地址
    u_int16_t minport;        // 端口范围（最小值）
    u_int16_t maxport;        // 端口范围（最大值）
    u_int8_t nat_type;        // NAT类型（源NAT或目的NAT）
};

// 连接追踪结构体，用于在 CLI 和内核间传递连接状态信息
struct ConnTrackInfo {
    u_int32_t saddr;   // 源IP地址
    u_int32_t daddr;   // 目的IP地址
    u_int16_t sport;   // 源端口
    u_int16_t dport;   // 目的端口
    u_int8_t protocol; // 协议类型
    u_int8_t state;    // 连接状态
};

// Netlink 消息发送函数声明
int init_netlink_socket(void);
void send_netlink_msg(uint8_t command, void *data, uint16_t data_len);
void receive_netlink_response(char *response, size_t response_size);

// CLI 命令处理函数声明
void add_rule(struct IPRule *rule);                 // 添加防火墙规则
void del_rule(const char *rule_name);               // 删除防火墙规则
void list_rules(void);                              // 列出所有防火墙规则
void save_rules(const char *filepath);              // 保存防火墙规则
void load_rules(const char *filepath);              // 加载防火墙规则
void add_nat_rule(struct NATRule *rule);            // 添加 NAT 规则
void del_nat_rule(const char *rule_name);           // 删除 NAT 规则
void list_nat_rules(void);                          // 列出所有 NAT 规则
void list_nat_records(void);                        // 列出所有 NAT 记录
void flush_logs(void);                              // 清空日志
void get_logs(void);                                // 获取日志
void query_conn(void);                              // 查询连接状态
void clear_conn(void);                              // 清除连接信息
void set_default_action(uint8_t action);            // 设置默认动作

#endif // FWCLI_H
