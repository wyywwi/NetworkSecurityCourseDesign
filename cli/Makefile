# 编译器
CC = gcc

# 编译标志
CFLAGS = -I./include -Wall -std=c99

# 可执行文件
TARGET = fwcli

# 源文件和对象文件
SRCS = fwcli.c fwcli_cmds.c fwcli_nl.c
OBJS = $(SRCS:.c=.o)

# 生成目标文件
build: $(TARGET)
	@rm -f $(OBJS)

# 生成可执行文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# 编译源文件为对象文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理编译生成的文件
clean:
	rm -f $(OBJS) $(TARGET)

# 伪目标
.PHONY: build clean
