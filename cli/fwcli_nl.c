#include "fwcli.h"

// 定义Netlink套接字的文件描述符
static int sock_fd = -1;

// 初始化 Netlink 套接字，返回 0 表示成功，-1 表示失败
int init_netlink_socket(void) {
    struct sockaddr_nl src_addr;

    // 创建一个 Netlink 套接字
    sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0) {
        perror("socket");
        return -1;
    }

    // 绑定本地 Netlink 套接字地址
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); // 本进程的PID
    src_addr.nl_groups = 0; // 不加入任何组

    if (bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) < 0) {
        perror("bind");
        close(sock_fd);
        return -1;
    }

    return 0;
}

// 发送 Netlink 消息，包含命令和数据
void send_netlink_msg(uint8_t command, void *data, uint16_t data_len) {
    struct nlmsghdr *nlh;
    struct sockaddr_nl dest_addr;
    struct iovec iov;
    struct msghdr msg;
    struct NetlinkMessage *nl_msg;

    // 为 Netlink 消息分配空间
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(struct NetlinkMessage) + data_len));
    if (!nlh) {
        perror("malloc");
        return;
    }
    memset(nlh, 0, NLMSG_SPACE(sizeof(struct NetlinkMessage) + data_len));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(struct NetlinkMessage) + data_len);
    nlh->nlmsg_pid = getpid(); // 发送进程的PID
    nlh->nlmsg_flags = 0; // 默认标志

    // 构建 Netlink 消息
    nl_msg = (struct NetlinkMessage *)NLMSG_DATA(nlh);
    nl_msg->command = command;
    nl_msg->data_len = data_len;
    if (data && data_len > 0) {
        memcpy(nl_msg->data, data, data_len);
    }

    // 设置目标地址（内核地址）
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // 内核

    // 构建消息
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 发送消息到内核
    if (sendmsg(sock_fd, &msg, 0) < 0) {
        perror("sendmsg");
    }

    // 释放内存
    free(nlh);
}

// 接收 Netlink 响应消息
void receive_netlink_response(char *response, size_t response_size) {
    struct nlmsghdr *nlh;
    struct iovec iov;
    struct msghdr msg;

    // 为接收消息分配空间
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(response_size));
    if (!nlh) {
        perror("malloc");
        return;
    }
    memset(nlh, 0, NLMSG_SPACE(response_size));

    // 构建消息缓冲区
    iov.iov_base = (void *)nlh;
    iov.iov_len = NLMSG_SPACE(response_size);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 接收消息
    if (recvmsg(sock_fd, &msg, 0) < 0) {
        perror("recvmsg");
        free(nlh);
        return;
    }

    // 拷贝数据到响应缓冲区
    memcpy(response, NLMSG_DATA(nlh), response_size);

    // 释放内存
    free(nlh);
}

// 关闭 Netlink 套接字
void close_netlink_socket(void) {
    if (sock_fd >= 0) {
        close(sock_fd);
    }
}
