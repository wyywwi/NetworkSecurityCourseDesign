# 定义子目录
CLI_DIR = ./cli
KERNEL_DIR = ./kernel

# QEMU 配置
QEMU_SYSTEM = qemu-system-x86_64
QEMU_IMAGE = ./qemu_images/initrd.img
QEMU_KERNEL = ./qemu_images/vmlinuz
QEMU_MEMORY = 512M
QEMU_NET = user,hostfwd=tcp::10022-:22  # 用于端口转发，将虚拟机的 22 端口映射到主机的 10022 端口
QEMU_WORKDIR = /root/firewall_test
SSH_USER = root
SSH_PASS = root

# Docker 容器和网络配置
DOCKER_IMAGE = dockerpull.com/ubuntu:20.04
FIREWALL_CONTAINER = firewall_gateway
CLIENT_CONTAINER = firewall_client
INTERNAL_NET = internal_net
EXTERNAL_NET = external_net
DOCKER_WORKDIR = /root/firewall_test

# 获取当前目录绝对路径
CURRENT_DIR := $(shell pwd)

# 默认目标
.PHONY: all
all: build

# 编译 CLI 和 kernel 模块
.PHONY: build
build:
	@echo "Building CLI and Kernel modules..."
	$(MAKE) -C $(CLI_DIR) CFLAGS="-I./include -std=c99" build
	$(MAKE) -C $(KERNEL_DIR) EXTRA_CFLAGS="-I$(CURRENT_DIR)/$(KERNEL_DIR)/include" build

# QEMU 启动虚拟机并测试内核模块
.PHONY: qemu
qemu: build
	@echo "Starting QEMU virtual machine for kernel module testing..."
	$(QEMU_SYSTEM) -nographic -m $(QEMU_MEMORY) -kernel $(QEMU_KERNEL) -hda $(QEMU_IMAGE) \
		-append "root=/dev/sda console=ttyS0" -net nic -net $(QEMU_NET) \
		-nographic -enable-kvm &  # 后台启动虚拟机

	@echo "Waiting for the QEMU VM to boot..."
	@sleep 10  # 等待虚拟机启动，实际可以使用更智能的等待机制

	@echo "Transferring kernel modules and CLI files to QEMU VM..."
	# 通过 SSH 将编译好的文件传输到 QEMU 虚拟机中
	@scp -P 10022 $(CLI_DIR)/fwcli $(KERNEL_DIR)/*.ko $(SSH_USER)@localhost:$(QEMU_WORKDIR)

	@echo "Loading kernel module in QEMU VM..."
	# 通过 SSH 登录到 QEMU 虚拟机并加载内核模块
	@sshpass -p $(SSH_PASS) ssh -p 10022 $(SSH_USER)@localhost "insmod $(QEMU_WORKDIR)/kernel/firewall.ko"

	@echo "QEMU environment setup complete!"
	@echo "To interact with the QEMU VM, use the following command:"
	@echo "  ssh -p 10022 $(SSH_USER)@localhost"

# 清理 QEMU 进程（停止虚拟机）
.PHONY: stop-qemu
stop-qemu:
	@echo "Stopping QEMU virtual machine..."
	# 通过 SSH 登录虚拟机并关闭系统
	@sshpass -p $(SSH_PASS) ssh -p 10022 $(SSH_USER)@localhost "poweroff" || true
	@echo "QEMU virtual machine stopped."

# 封装 Docker 环境的创建与测试为 docker 目标，并确保编译过程
.PHONY: docker
docker: build
	@echo "Setting up Docker environment..."
	
	# 创建 Docker 网络（内网和外网）
	@if ! docker network ls | grep -q $(INTERNAL_NET); then \
		echo "Creating internal network $(INTERNAL_NET)..."; \
		docker network create $(INTERNAL_NET); \
	fi

	@if ! docker network ls | grep -q $(EXTERNAL_NET); then \
		echo "Creating external network $(EXTERNAL_NET)..."; \
		docker network create $(EXTERNAL_NET); \
	fi

	# 检查是否存在防火墙和客户端容器，若存在则移除并重建
	@if [ "`docker ps -a | grep $(FIREWALL_CONTAINER)`" ]; then \
		echo "Removing existing firewall container..."; \
		docker rm -f $(FIREWALL_CONTAINER); \
	fi

	@if [ "`docker ps -a | grep $(CLIENT_CONTAINER)`" ]; then \
		echo "Removing existing client container..."; \
		docker rm -f $(CLIENT_CONTAINER); \
	fi

	# 启动防火墙网关容器并连接到外网和内网
	@echo "Starting firewall gateway container..."
	docker run -d --name $(FIREWALL_CONTAINER) --privileged \
		--network $(EXTERNAL_NET) \
		-v $(shell pwd):$(DOCKER_WORKDIR) \
		-it $(DOCKER_IMAGE) bash

	# 将防火墙网关容器连接到内网
	@echo "Connecting firewall gateway to internal network..."
	docker network connect $(INTERNAL_NET) $(FIREWALL_CONTAINER)

	# 启动客户端容器，并连接到内网
	@echo "Starting client container..."
	docker run -d --name $(CLIENT_CONTAINER) \
		--network $(INTERNAL_NET) \
		-v $(shell pwd):$(DOCKER_WORKDIR) \
		-it $(DOCKER_IMAGE) bash

	# 将编译得到的文件复制到防火墙容器中
	@echo "Copying compiled files to Docker containers..."
	docker cp $(CLI_DIR)/fwcli $(FIREWALL_CONTAINER):$(DOCKER_WORKDIR)/cli/
	docker cp $(KERNEL_DIR)/*.ko $(FIREWALL_CONTAINER):$(DOCKER_WORKDIR)/kernel/

	# 在防火墙容器中安装 kmod 工具以提供 insmod 命令
	@echo "Installing kmod tools in firewall gateway..."
	docker exec -it $(FIREWALL_CONTAINER) bash -c "apt-get update && apt-get install -y kmod"

	# 在防火墙容器中加载内核模块
	@echo "Loading kernel modules in firewall gateway..."
	# docker exec -it $(FIREWALL_CONTAINER) bash -c "insmod $(DOCKER_WORKDIR)/kernel/firewall.ko"

	@echo "Docker environment setup complete!"
	@echo "To interact with the containers, use the following commands:"
	@echo "sudo docker exec -it $(FIREWALL_CONTAINER) bash -c 'cd $(DOCKER_WORKDIR)/cli && bash'    # Access the firewall gateway in cli directory"
	@echo "sudo docker exec -it $(CLIENT_CONTAINER) bash      # Access the client"

# 清理 Docker 容器、网络
.PHONY: clean
clean:
	@echo "Cleaning up..."
	$(MAKE) -C $(CLI_DIR) clean
	$(MAKE) -C $(KERNEL_DIR) clean

	# 停止 QEMU 虚拟机
	$(MAKE) stop-qemu

	# 停止并移除 Docker 容器
	@if [ "`docker ps -a | grep $(FIREWALL_CONTAINER)`" ]; then \
		echo "Removing firewall gateway container..."; \
		docker rm -f $(FIREWALL_CONTAINER); \
	fi

	@if [ "`docker ps -a | grep $(CLIENT_CONTAINER)`" ]; then \
		echo "Removing client container..."; \
		docker rm -f $(CLIENT_CONTAINER); \
	fi

	# 移除 Docker 网络
	@if docker network ls | grep -q $(INTERNAL_NET); then \
		echo "Removing internal network..."; \
		docker network rm $(INTERNAL_NET); \
	fi

	@if docker network ls | grep -q $(EXTERNAL_NET); then \
		echo "Removing external network..."; \
		docker network rm $(EXTERNAL_NET); \
	fi
