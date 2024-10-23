# 内核模块对象文件列表
obj-m += firewall.o

# 组成防火墙模块的对象文件列表
firewall-objs := mod.o hook_main.o conn.o rule.o netlink.o nat.o log.o

# 包含头文件的路径
EXTRA_CFLAGS := -I$(PWD)/include

# 内核目录和当前工作目录定义
KDIR := /lib/modules/$(shell uname -r)/build  # 当前运行内核的构建目录路径
PWD := $(shell pwd)  # 当前工作目录路径

# 编译内核模块
build:
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules
	@rm -f *.o *.mod.o *.mod.c *.symvers *.order *.ko.cmd *.o.cmd *.tmp_versions

# 清理构建文件
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@rm -f *.o *.mod.o *.mod.c *.symvers *.order *.ko.cmd *.o.cmd
	@rm -rf .tmp_versions

# 伪目标
.PHONY: build clean
