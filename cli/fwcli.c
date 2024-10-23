#include "fwcli.h"

void print_help() {
    printf("Usage: firewall_cli [command] [options]\n");
    printf("Commands:\n");
    printf("  add_rule --name <name> --saddr <ip> --smask <mask> --daddr <ip> --dmask <mask> --sport <minport> --dport <minport> --protocol <tcp/udp> --action <accept/drop>\n");
    printf("  del_rule --name <name>\n");
    printf("  list_rules\n");
    printf("  save_rules <filepath>\n");
    printf("  load_rules <filepath>\n");
    printf("  add_nat_rule --name <name> --saddr <ip> --daddr <ip> --minport <port> --maxport <port> --nat_type <src/dest>\n");
    printf("  del_nat_rule --name <name>\n");
    printf("  list_nat_rules\n");
    printf("  list_nat_records\n");
    printf("  flush_logs\n");
    printf("  get_logs\n");
    printf("  query_conn\n");
    printf("  clear_conn\n");
    printf("  set_default --action <accept/drop>\n");
}

// 解析布尔选项
int parse_action(const char *action_str) {
    if (strcmp(action_str, "accept") == 0) {
        return 1;
    } else if (strcmp(action_str, "drop") == 0) {
        return 0;
    } else {
        printf("Invalid action: %s. Must be 'accept' or 'drop'.\n", action_str);
        exit(1);
    }
}

int parse_protocol(const char *protocol_str) {
    if (strcmp(protocol_str, "tcp") == 0) {
        return IPPROTO_TCP;
    } else if (strcmp(protocol_str, "udp") == 0) {
        return IPPROTO_UDP;
    } else {
        printf("Invalid protocol: %s. Must be 'tcp' or 'udp'.\n", protocol_str);
        exit(1);
    }
}

int parse_nat_type(const char *nat_type_str) {
    if (strcmp(nat_type_str, "src") == 0) {
        return NAT_TYPE_SRC;
    } else if (strcmp(nat_type_str, "dest") == 0) {
        return NAT_TYPE_DEST;
    } else {
        printf("Invalid NAT type: %s. Must be 'src' or 'dest'.\n", nat_type_str);
        exit(1);
    }
    return 0;
}

// 解析并执行命令
void parse_and_execute_command(int argc, char *argv[]) {
    if (argc < 2) {
        print_help();
        return;
    }

    const char *command = argv[1];

    if (strcmp(command, "add_rule") == 0) {
        struct IPRule rule;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--name") == 0) {
                strcpy(rule.name, argv[++i]);
            } else if (strcmp(argv[i], "--saddr") == 0) {
                rule.saddr = inet_addr(argv[++i]);
            } else if (strcmp(argv[i], "--smask") == 0) {
                rule.smask = inet_addr(argv[++i]);
            } else if (strcmp(argv[i], "--daddr") == 0) {
                rule.daddr = inet_addr(argv[++i]);
            } else if (strcmp(argv[i], "--dmask") == 0) {
                rule.dmask = inet_addr(argv[++i]);
            } else if (strcmp(argv[i], "--sport") == 0) {
                rule.sport_min = atoi(argv[++i]);
                rule.sport_max = rule.sport_min;
            } else if (strcmp(argv[i], "--dport") == 0) {
                rule.dport_min = atoi(argv[++i]);
                rule.dport_max = rule.dport_min;
            } else if (strcmp(argv[i], "--protocol") == 0) {
                rule.protocol = parse_protocol(argv[++i]);
            } else if (strcmp(argv[i], "--action") == 0) {
                rule.action = parse_action(argv[++i]);
            }
        }
        add_rule(&rule);

    } else if (strcmp(command, "del_rule") == 0) {
        if (argc != 4 || strcmp(argv[2], "--name") != 0) {
            print_help();
            return;
        }
        del_rule(argv[3]);

    } else if (strcmp(command, "list_rules") == 0) {
        list_rules();

    } else if (strcmp(command, "save_rules") == 0) {
        if (argc != 3) {
            print_help();
            return;
        }
        save_rules(argv[2]);

    } else if (strcmp(command, "load_rules") == 0) {
        if (argc != 3) {
            print_help();
            return;
        }
        load_rules(argv[2]);

    } else if (strcmp(command, "add_nat_rule") == 0) {
        struct NATRule rule;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--name") == 0) {
                strcpy(rule.name, argv[++i]);
            } else if (strcmp(argv[i], "--saddr") == 0) {
                rule.saddr = inet_addr(argv[++i]);
            } else if (strcmp(argv[i], "--daddr") == 0) {
                rule.daddr = inet_addr(argv[++i]);
            } else if (strcmp(argv[i], "--minport") == 0) {
                rule.minport = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--maxport") == 0) {
                rule.maxport = atoi(argv[++i]);
            } else if (strcmp(argv[i], "--nat_type") == 0) {
                rule.nat_type = parse_nat_type(argv[++i]);
            }
        }
        add_nat_rule(&rule);

    } else if (strcmp(command, "del_nat_rule") == 0) {
        if (argc != 4 || strcmp(argv[2], "--name") != 0) {
            print_help();
            return;
        }
        del_nat_rule(argv[3]);

    } else if (strcmp(command, "list_nat_rules") == 0) {
        list_nat_rules();

    } else if (strcmp(command, "list_nat_records") == 0) {
        list_nat_records();

    } else if (strcmp(command, "flush_logs") == 0) {
        flush_logs();

    } else if (strcmp(command, "get_logs") == 0) {
        get_logs();

    } else if (strcmp(command, "query_conn") == 0) {
        query_conn();

    } else if (strcmp(command, "clear_conn") == 0) {
        clear_conn();

    } else if (strcmp(command, "set_default") == 0) {
        if (argc != 4 || strcmp(argv[2], "--action") != 0) {
            print_help();
            return;
        }
        uint8_t action = parse_action(argv[3]);
        set_default_action(action);

    } else {
        printf("Unknown command: %s\n", command);
        print_help();
    }
}

int main(int argc, char *argv[]) {
    // 初始化 Netlink 套接字
    if (init_netlink_socket() < 0) {
        printf("Failed to initialize Netlink socket.\n");
        return 1;
    }

    // 解析并执行命令
    parse_and_execute_command(argc, argv);

    // 关闭 Netlink 套接字
    close_netlink_socket();
    return 0;
}
