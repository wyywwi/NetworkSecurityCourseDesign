#include "fwcli.h"

// 添加防火墙规则
void add_rule(struct IPRule *rule) {
    // 发送 add_rule 的 Netlink 消息
    send_netlink_msg(CMD_ADD_RULE, rule, sizeof(struct IPRule));

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Add Rule Response: %s\n", response);
}

// 删除防火墙规则
void del_rule(const char *rule_name) {
    // 发送 del_rule 的 Netlink 消息
    send_netlink_msg(CMD_DEL_RULE, rule_name, strlen(rule_name) + 1);

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Delete Rule Response: %s\n", response);
}

// 列出所有防火墙规则
void list_rules(void) {
    // 发送 list_rules 的 Netlink 消息
    send_netlink_msg(CMD_LIST_RULES, NULL, 0);

    // 接收并处理内核响应
    char response[4096];
    receive_netlink_response(response, sizeof(response));
    printf("Firewall Rules:\n%s\n", response);
}

// 保存防火墙规则
void save_rules(const char *filepath) {
    // 发送 save_rules 的 Netlink 消息
    send_netlink_msg(CMD_SAVE_RULES, filepath, strlen(filepath) + 1);

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Save Rules Response: %s\n", response);
}

// 加载防火墙规则
void load_rules(const char *filepath) {
    // 发送 load_rules 的 Netlink 消息
    send_netlink_msg(CMD_LOAD_RULES, filepath, strlen(filepath) + 1);

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Load Rules Response: %s\n", response);
}

// 添加 NAT 规则
void add_nat_rule(struct NATRule *rule) {
    // 发送 add_nat_rule 的 Netlink 消息
    send_netlink_msg(CMD_ADD_NAT_RULE, rule, sizeof(struct NATRule));

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Add NAT Rule Response: %s\n", response);
}

// 删除 NAT 规则
void del_nat_rule(const char *rule_name) {
    // 发送 del_nat_rule 的 Netlink 消息
    send_netlink_msg(CMD_DEL_NAT_RULE, rule_name, strlen(rule_name) + 1);

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Delete NAT Rule Response: %s\n", response);
}

// 列出所有 NAT 规则
void list_nat_rules(void) {
    // 发送 list_nat_rules 的 Netlink 消息
    send_netlink_msg(CMD_LIST_NAT_RULES, NULL, 0);

    // 接收并处理内核响应
    char response[4096];
    receive_netlink_response(response, sizeof(response));
    printf("NAT Rules:\n%s\n", response);
}

// 列出所有 NAT 记录
void list_nat_records(void) {
    // 发送 list_nat_records 的 Netlink 消息
    send_netlink_msg(CMD_LIST_NAT_RECORDS, NULL, 0);

    // 接收并处理内核响应
    char response[4096];
    receive_netlink_response(response, sizeof(response));
    printf("NAT Records:\n%s\n", response);
}

// 清空日志
void flush_logs(void) {
    // 发送 flush_logs 的 Netlink 消息
    send_netlink_msg(CMD_FLUSH_LOGS, NULL, 0);

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Flush Logs Response: %s\n", response);
}

// 获取日志
void get_logs(void) {
    // 发送 get_logs 的 Netlink 消息
    send_netlink_msg(CMD_GET_LOGS, NULL, 0);

    // 接收并处理内核响应
    char response[4096];
    receive_netlink_response(response, sizeof(response));
    printf("Logs:\n%s\n", response);
}

// 查询连接状态
void query_conn(void) {
    // 发送 query_conn 的 Netlink 消息
    send_netlink_msg(CMD_QUERY_CONN, NULL, 0);

    // 接收并处理内核响应
    char response[4096];
    receive_netlink_response(response, sizeof(response));
    printf("Connection Info:\n%s\n", response);
}

// 清除连接信息
void clear_conn(void) {
    // 发送 clear_conn 的 Netlink 消息
    send_netlink_msg(CMD_CLEAR_CONN, NULL, 0);

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Clear Connection Response: %s\n", response);
}

// 设置默认动作
void set_default_action(uint8_t action) {
    // 发送 set_default_action 的 Netlink 消息
    send_netlink_msg(CMD_SET_DEFAULT, &action, sizeof(uint8_t));

    // 接收并处理内核响应
    char response[256];
    receive_netlink_response(response, sizeof(response));
    printf("Set Default Action Response: %s\n", response);
}
