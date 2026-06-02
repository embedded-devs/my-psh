# =====================================================
# Makefile for psh_demo2
# =====================================================

CC      := gcc
CFLAGS  := -Wall -O2
LDFLAGS :=

# ---- Git 版本信息 ----
# 获取 git 提交哈希（短格式）、提交日期、提交计数、分支名、是否脏（有未提交修改）
GIT_HASH    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "nogit")
GIT_DATE    := $(shell git log -1 --format=%cd --date=format:%Y%m%d 2>/dev/null || echo "19700101")
GIT_COUNT   := $(shell git rev-list --count HEAD 2>/dev/null || echo "0")
GIT_BRANCH  := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GIT_DIRTY   := $(shell git diff --quiet HEAD 2>/dev/null || echo "-dirty")

# 组合版本字符串: SM-<日期>-<提交哈希>-<提交计数>[-dirty]
# 示例: SM-20250602-a1b2c3d-42-dirty
PSH_VERSION := SM-$(GIT_DATE)-$(GIT_HASH)-n$(shell printf '%06d' $(GIT_COUNT))$(GIT_DIRTY)

# 通过 -D 宏将版本信息传递给 C 代码
CFLAGS      += -DPSH_VERSION=\"$(PSH_VERSION)\"

PROJ_ROOT   := $(shell pwd)
LIBS_DIR    := $(PROJ_ROOT)/libs

# ---- 头文件目录 ----
INC_DIRS :=
INC_DIRS += $(LIBS_DIR)/libqrencode-4.1.1/_install/include
INC_DIRS += $(LIBS_DIR)/mbedtls-4.0.0/_install/include

# ---- 库文件目录 ----
LIB_DIRS :=
LIB_DIRS += $(LIBS_DIR)/libqrencode-4.1.1/_install/lib
LIB_DIRS += $(LIBS_DIR)/mbedtls-4.0.0/_install/lib

# ---- 链接库 ----
LIBS :=
LIBS += qrencode
LIBS += mbedtls
LIBS += mbedx509
LIBS += mbedcrypto
LIBS += pthread

# ---- 自动生成编译选项 ----
LIB_INC   := $(addprefix -I,$(INC_DIRS))
LIB_LIB   := $(addprefix -L,$(LIB_DIRS)) $(addprefix -l,$(LIBS))

TARGET := psh
SRCS   := $(wildcard *.c src/*.c)
OBJS   := $(SRCS:%.c=%.o)

.PHONY: all build clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIB_LIB) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(LIB_INC) -c $< -o $@

build: $(TARGET)

run: $(TARGET)
	./$(TARGET) "Hello, QR Code!"

clean:
	rm -f $(TARGET) $(OBJS)
