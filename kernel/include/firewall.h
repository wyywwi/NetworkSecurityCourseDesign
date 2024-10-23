#ifndef FIREWALL_H
#define FIREWALL_H

#include "dependency.h"

/* 常量与结构体定义 */

#define CONN_TABLE_SIZE 1024 // 连接状态表的哈希表大小

#define CLEANUP_INTERVAL (5 * HZ) // 超时处理：每5秒清理一次

#define LOG_FILE_PATH "/var/log/rxfirewall.log" // 保存日志的文件路径

// NAT相关
#define NAT_TYPE_DEST 1
#define NAT_TYPE_SRC  2

// 通用状态
#define STATE_CLOSED      0x00  // 连接已关闭

// TCP 状态
#define TCP_STATE_SYN_SENT     0x10  // 16
#define TCP_STATE_SYN_RECV     0x11  // 17
#define TCP_STATE_ESTABLISHED  0x12  // 18
#define TCP_STATE_FIN_WAIT     0x13  // 19
#define TCP_STATE_CLOSED       STATE_CLOSED  // TCP 关闭状态

// UDP 状态
#define UDP_STATE_NEW          0x20  // 32
#define UDP_STATE_ESTABLISHED  0x21  // 33
#define UDP_STATE_CLOSED       STATE_CLOSED  // UDP 关闭状态

// ICMP 状态
#define ICMP_STATE_ECHO_REQUEST 0x30  // 48
#define ICMP_STATE_ECHO_REPLY   0x31  // 49
#define ICMP_STATE_CLOSED       STATE_CLOSED  // ICMP 关闭状态

// 日志类型定义
#define LOG_TYPE_INFO 0         // 信息日志
#define LOG_TYPE_WARNING 1      // 警告日志
#define LOG_TYPE_ERROR 2        // 错误日志
#define LOG_TYPE_DROP 3         // 丢弃日志
#define LOG_TYPE_ACCEPT 4       // 接受日志
#define LOG_TYPE_BLOCK 5        // 阻断日志
#define LOG_TYPE_CONN_ESTABLISHED 6 // 连接建立日志
#define LOG_TYPE_CONN_TERMINATED 7  // 连接终止日志
#define LOG_TYPE_NAT 8          // NAT日志
#define LOG_TYPE_ADMIN 9        // 管理日志

// Netlink 错误码定义 (Error codes for Netlink communication)
#define ERR_OK 0                // 操作成功完成 (Operation completed successfully)
#define ERR_INVALID_CMD 1       // 无效的命令 (Invalid command received)
#define ERR_NO_MEMORY 2         // 内存不足 (Insufficient memory to complete the operation)
#define ERR_RULE_EXISTS 3       // 规则已存在 (Rule already exists)
#define ERR_RULE_NOT_FOUND 4    // 规则未找到 (Rule not found)
#define ERR_NAT_RULE_EXISTS 5   // NAT 规则已存在 (NAT rule already exists)
#define ERR_NAT_RULE_NOT_FOUND 6 // NAT 规则未找到 (NAT rule not found)
#define ERR_CONN_NOT_FOUND 7    // 连接未找到 (Connection not found)
#define ERR_LOG_EMPTY 8         // 日志为空 (No logs available)
#define ERR_NETLINK_FAIL 9      // Netlink 通信失败 (Netlink communication failure)
#define ERR_INVALID_ARGS 10     // 参数无效 (Invalid arguments provided)
#define ERR_UNKNOWN 99          // 未知错误 (Unknown error occurred)

// Netlink 操作码定义 (Netlink command opcodes)
#define CMD_ADD_RULE 0x01           // 添加防火墙规则 (Add a firewall rule)
#define CMD_DEL_RULE 0x02           // 删除防火墙规则 (Delete a firewall rule)
#define CMD_LIST_RULES 0x03         // 列出所有防火墙规则 (List all firewall rules)
#define CMD_SAVE_RULES 0x04         // 保存防火墙规则到文件 (Save firewall rules to a file)
#define CMD_LOAD_RULES 0x05         // 从文件加载防火墙规则 (Load firewall rules from a file)
#define CMD_QUERY_CONN 0x06         // 查询连接状态 (Query connection status)
#define CMD_CLEAR_CONN 0x07         // 清理所有连接 (Clear all tracked connections)
#define CMD_ADD_NAT_RULE 0x08       // 添加 NAT 规则 (Add a NAT rule)
#define CMD_DEL_NAT_RULE 0x09       // 删除 NAT 规则 (Delete a NAT rule)
#define CMD_LIST_NAT_RULES 0x0A     // 列出所有 NAT 规则 (List all NAT rules)
#define CMD_LIST_NAT_RECORDS 0x0B     // 列出所有 NAT 记录 (List all NAT records)
#define CMD_FLUSH_LOGS 0x0C         // 清空所有防火墙日志 (Flush all firewall logs)
#define CMD_GET_LOGS 0x0D           // 获取所有防火墙日志 (Get all firewall logs)
#define CMD_SET_DEFAULT 0x0E        // 设置默认动作（接受或丢弃）(Set the default action for unmatched packets: accept or drop)
#define CMD_UNKNOWN 0xFF            // 未知命令 (Unknown command)

// 日志条目结构体定义
struct LogEntry {
    u_int8_t log_type;                // 日志类型
    struct timespec64 timestamp;      // 日志的时间戳
    u_int32_t saddr;                  // 源 IP 地址
    u_int32_t daddr;                  // 目的 IP 地址
    u_int16_t sport;                  // 源端口
    u_int16_t dport;                  // 目的端口
    char message[128];                // 日志消息
    struct LogEntry *next;            // 指向下一个日志条目的指针
};

// 防火墙规则表结构
struct IPRule {
    char name[32];            // 规则名称，最大长度31字节 + 1字节的'\0'
    u_int32_t saddr;          // 源IP地址
    u_int32_t smask;          // 源IP掩码，用于匹配子网
    u_int32_t daddr;          // 目的IP地址
    u_int32_t dmask;          // 目的IP掩码，用于匹配子网
    u_int16_t sport_min;      // 源端口范围，最小端口值
    u_int16_t sport_max;      // 源端口范围，最大端口值
    u_int16_t dport_min;      // 目的端口范围，最小端口值
    u_int16_t dport_max;      // 目的端口范围，最大端口值
    u_int8_t protocol;        // 协议类型（TCP、UDP等）
    u_int8_t action;          // 动作：0表示丢弃，1表示接受
    struct IPRule* next;      // 指向下一条规则的指针（链表）
};

// NAT规则表结构
struct NATRule {
    char name[32];            // 规则名称，最大长度31字节 + 1字节的'\0'
    u_int32_t saddr;          // 外部IP地址
    u_int32_t smask;          // 外部IP掩码
    u_int32_t daddr;          // 需要NAT转换的内部IP地址
    u_int16_t minport;        // 网关端口范围：最小值
    u_int16_t maxport;        // 网关端口范围：最大值
    u_int8_t nat_type;        // NAT类型（NAT_TYPE_SRC 或 NAT_TYPE_DEST）
    struct NATRule* next;     // 指向下一个 NAT 规则的指针（链表）
};

// NAT记录表结构
struct NATRecord {
    u_int32_t saddr;          // 原始IP地址
    u_int32_t daddr;          // NAT转换后的IP地址
    u_int16_t sport;          // 原始端口
    u_int16_t dport;          // 转换后端口
    u_int8_t nat_type;        // NAT类型（NAT_TYPE_SRC 或 NAT_TYPE_DEST）
    struct NATRecord* next;   // 指向下一个NAT记录的指针（链表）
};

// NAT 日志表结构，用于记录每次 NAT 操作的日志
struct NATLog {
    u_int64_t timestamp;      // NAT 操作的时间戳
    u_int32_t original_saddr; // 原始源IP地址
    u_int32_t translated_daddr; // NAT转换后的目标IP地址
    u_int16_t original_sport; // 原始源端口
    u_int16_t translated_dport; // NAT转换后的目标端口
    u_int8_t nat_type;        // NAT 类型（NAT_TYPE_SRC 或 NAT_TYPE_DEST）
    struct NATLog* next;      // 指向下一个 NAT 日志的指针（链表）
};

// 连接标识符结构体
typedef struct conn_key_t {
    u_int32_t saddr;   // 源IP地址
    u_int32_t daddr;   // 目的IP地址
    u_int16_t sport;   // 源端口
    u_int16_t dport;   // 目的端口
    u_int8_t protocol; // 协议类型 (TCP, UDP, ICMP等)
} conn_key_t;

// 连接记录表结构
struct ConnTrackHash {
    conn_key_t key;            // 连接标识符（包括源IP、目的IP、源端口、目的端口、协议）
    u_int8_t state;            // 连接状态
    unsigned long expires;     // 绝对超时时间戳 (比较宏要求使用ul)
    u_int8_t direction;        // 连接方向，0表示入站，1表示出站
    struct NATRecord* nat;     // 指向NAT记录的指针（如有NAT）
    struct timespec64 timestamp;  // 记录连接的开始时间或上次活动时间，用于超时清理
    struct ConnTrackHash* next; // 用于解决哈希冲突的链表指针
};

/* 函数声明 */

// 钩子函数的声明
unsigned int hook_main(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// NAT钩子函数的声明
unsigned int hook_nat_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int hook_nat_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

// 钩子函数的初始化和清理
int hook_init(void);
void hook_exit(void);

// 日志管理
void log_init(void);
void log_exit(void);
void flush_logs(void);
void list_logs(void);
void add_log_entry(u_int8_t log_type, u_int32_t saddr, u_int32_t daddr, u_int16_t sport, u_int16_t dport, const char *message);

// 连接状态表的管理
extern struct ConnTrackHash* conn_table[CONN_TABLE_SIZE];
extern u_int8_t default_action;

void conn_init(void);
void conn_exit(void);
struct ConnTrackHash* find_conn_in_table(conn_key_t key);
void insert_conn_into_table(struct ConnTrackHash* new_conn);
struct ConnTrackHash* create_new_conn(conn_key_t key, void* header);
bool update_tcp_state(struct ConnTrackHash* conn, struct tcphdr* tcp_header);
void update_conn_expires(struct ConnTrackHash* conn);
void send_all_conn_info_via_netlink(void);
int clear_conn(void);

// 规则表管理
int save_rules(const char *filepath);
int load_rules(const char *filepath);
int add_rule(struct IPRule* new_rule);
int modify_rule(const char* rule_name, struct IPRule* new_rule);
int del_rule(const char* rule_name);
void list_rules(void);
int match_rules(struct iphdr* ip_header, void* transport_header);

// NAT管理
extern struct NATRule *nat_rules_head;

struct NATRecord* get_nat_record(u_int32_t addr, u_int16_t port, u_int32_t naddr, u_int8_t nat_type);
int add_nat_rule(struct NATRule *new_rule);
int del_nat_rule(const char *rule_name);
void apply_dnat(struct iphdr *ip_header, struct sk_buff *skb, struct NATRecord *nat_record);
void apply_snat(struct iphdr *ip_header, struct sk_buff *skb, struct NATRecord *nat_record);
int send_all_nat_rules_via_netlink(void);
int send_all_nat_records_via_netlink(void);

// Netlink通信的管理
extern struct sock *nl_sk;

int netlink_init(void);
void netlink_exit(void);

#endif // FIREWALL_H
