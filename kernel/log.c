#include "firewall.h"

#define MAX_LOG_ENTRIES 10000  // 日志条目的最大数量

static struct LogEntry *log_head = NULL;  // 日志链表的头指针
static int log_entry_count = 0;  // 当前日志条目的数量
static DEFINE_MUTEX(log_lock);  // 日志锁，确保多线程安全

// 添加日志条目
void add_log_entry(u_int8_t log_type, u_int32_t saddr, u_int32_t daddr, u_int16_t sport, u_int16_t dport, const char *message) {
    struct LogEntry *new_entry;
    struct timespec64 current_time;

    if (log_entry_count >= MAX_LOG_ENTRIES) {
        printk(KERN_WARNING "Firewall: Log entry limit reached, flushing logs\n");
        return;
    }

    new_entry = kmalloc(sizeof(struct LogEntry), GFP_KERNEL);
    if (!new_entry) {
        printk(KERN_ERR "Firewall: Memory allocation for new log entry failed\n");
        return;
    }

    // 获取当前时间
    ktime_get_real_ts64(&current_time);
    new_entry->log_type = log_type;  // 设置日志类型
    new_entry->timestamp = current_time;
    new_entry->saddr = saddr;
    new_entry->daddr = daddr;
    new_entry->sport = sport;
    new_entry->dport = dport;
    snprintf(new_entry->message, sizeof(new_entry->message), "%s", message);

    // 添加到日志链表头部
    mutex_lock(&log_lock);
    new_entry->next = log_head;
    log_head = new_entry;
    log_entry_count++;
    mutex_unlock(&log_lock);
}

// 列出所有日志条目并通过 netlink 返回
void list_logs(void) {
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int msg_size = 16384;  // 假设消息大小足够容纳所有日志信息
    struct LogEntry *log = log_head;
    char *msg;

    // 为 netlink 消息分配内存
    skb = nlmsg_new(msg_size, GFP_KERNEL);
    if (!skb) {
        printk(KERN_ERR "Firewall: Failed to allocate netlink message\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, msg_size, 0);
    if (!nlh) {
        kfree_skb(skb);
        printk(KERN_ERR "Firewall: Failed to put netlink message\n");
        return;
    }

    msg = nlmsg_data(nlh);
    memset(msg, 0, msg_size);
    strcat(msg, "{\"logs\": [");

    // 遍历日志链表，打包日志信息为 JSON 格式
    mutex_lock(&log_lock);
    while (log) {
        snprintf(msg + strlen(msg), msg_size - strlen(msg),
                 "{\"type\": %u, \"timestamp\": \"%lld\", \"saddr\": \"%pI4\", \"daddr\": \"%pI4\", \"sport\": %u, \"dport\": %u, \"message\": \"%s\"}",
                 log->log_type, (long long)log->timestamp.tv_sec, &log->saddr, &log->daddr, log->sport, log->dport, log->message);
        log = log->next;
        if (log) {
            strcat(msg, ",");  // 添加逗号分隔多个日志条目
        }
    }
    mutex_unlock(&log_lock);
    strcat(msg, "]}");

    // 发送 netlink 消息
    NETLINK_CB(skb).dst_group = 0;  // 非多播
    nlmsg_unicast(nl_sk, skb, 0);
}

// 清空所有日志条目
void flush_logs(void) {
    struct LogEntry *log, *tmp;
    mutex_lock(&log_lock);
    log = log_head;
    while (log) {
        tmp = log;
        log = log->next;
        kfree(tmp);
    }
    log_head = NULL;
    log_entry_count = 0;
    mutex_unlock(&log_lock);
    printk(KERN_INFO "Firewall: All logs flushed\n");
}

// 保存所有日志到文件中（采用尾部新增方式）
void save_logs_to_file(void) {
    struct file *file;
    struct LogEntry *log;
    char buf[256];
    int bytes_written;
    loff_t pos = 0;

    // 打开文件
    file = filp_open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (IS_ERR(file)) {
        printk(KERN_ERR "Firewall: Failed to open log file for saving\n");
        return;
    }

    // 遍历日志链表并写入文件
    mutex_lock(&log_lock);
    log = log_head;
    while (log) {
        snprintf(buf, sizeof(buf), "Type: %u, Timestamp: %lld, Src: %pI4, Dst: %pI4, Sport: %u, Dport: %u, Message: %s\n",
                 log->log_type, (long long)log->timestamp.tv_sec, &log->saddr, &log->daddr, log->sport, log->dport, log->message);
        bytes_written = kernel_write(file, buf, strlen(buf), &pos);
        if (bytes_written < 0) {
            printk(KERN_ERR "Firewall: Failed to write log to file\n");
            break;
        }
        log = log->next;
    }
    mutex_unlock(&log_lock);

    // 关闭文件
    filp_close(file, NULL);

    printk(KERN_INFO "Firewall: Logs saved to file successfully\n");
}

// 日志模块初始化
void log_init(void) {
    log_head = NULL;
    printk(KERN_INFO "Firewall: Log module initialized\n");
}

// 日志模块退出
void log_exit(void) {
    save_logs_to_file();  // 保存日志到文件
    flush_logs();         // 清空所有日志
    printk(KERN_INFO "Firewall: Log module exited\n");
}
