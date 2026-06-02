/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : func_psh.c
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 1.0
 * Description: PSH（Protect Shell）受保护 Shell 模块实现
 *
 *  交互流程：
 *  ┌──────────────────────────────────────────┐
 *  │ BusyBox vx.x.x Protect Shell (psh)      │
 *  │ Enter 'help' for a list of commands.    │
 *  │                                          │
 *  │ # help          → 显示支持的命令         │
 *  │ # debug         → 生成挑战码 + QR 码     │
 *  │ # Password: *** → 输入短密钥解锁         │
 *  │ # ls            → 解锁后可执行任意命令   │
 *  └──────────────────────────────────────────┘
 *
 *  命令列表：
 *  - help  : 显示支持的命令
 *  - debug : 生成 RSA 挑战码（动态口令），显示为 QR 码 + Base64 文本
 *            并提示输入 8 字符短密钥进行解锁
 * ======================================================
 */

#include "func_psh.h"
#include "func_unlock.h"
#include "func_qrencode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>

/* ========== 常量定义 ========== */

/** PSH 版本信息 */
#define PSH_VERSION     "SM-20250602-n000001"

/** 最大命令行长度 */
#define PSH_CMD_MAX_LEN 256

/** 最大密码输入长度 */
#define PSH_PWD_MAX_LEN 32

/* ========== 内部辅助函数 ========== */

/** @fn static void psh_print_banner(void)
 *  @brief 打印 PSH 启动横幅信息
 */
static void psh_print_banner(void) {
    printf("BusyBox v1.36.1 Protect Shell (psh) ver: %s\n", PSH_VERSION);
    printf("Enter 'help' for a list of davinci system commands.\n");
}

/** @fn static void psh_print_prompt(void)
 *  @brief 打印命令提示符 "# "
 */
static void psh_print_prompt(void) {
    printf("# ");
    fflush(stdout);
}

/** @fn static void psh_read_line(char *buf, size_t size)
 *  @brief 从标准输入读取一行（去除末尾换行符）
 *  @param[out] buf  输出缓冲区
 *  @param[in]  size 缓冲区大小
 */
static void psh_read_line(char *buf, size_t size) {
    if (fgets(buf, (int)size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }

    /* 去除末尾换行符 */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }
}

/** @fn static void psh_read_password(char *buf, size_t size)
 *  @brief 读取密码输入（不回显），模拟设备端 Password 输入
 *  @param[out] buf  输出缓冲区
 *  @param[in]  size 缓冲区大小
 *  @note  使用 termios 关闭终端回显，输入完成后恢复
 */
static void psh_read_password(char *buf, size_t size) {
    struct termios old_term, new_term;

    /* 保存原始终端属性 */
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;

    /* 关闭回显标志 */
    new_term.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    /* 读取输入 */
    printf("Password:");
    fflush(stdout);

    if (fgets(buf, (int)size, stdin) == NULL) {
        buf[0] = '\0';
    }
    else {
        /* 去除末尾换行符 */
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
    }

    printf("\n");

    /* 恢复终端回显 */
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
}

/** @fn static void psh_cmd_help(void)
 *  @brief 处理 help 命令，显示支持的命令列表
 */
static void psh_cmd_help(void) {
    printf("Support Commands:\n");
    printf("%-32s%s\n", "help", "debug");
}

/** @fn static int psh_cmd_debug(void)
 *  @brief 处理 debug 命令：生成挑战码并提示输入解锁密钥
 *  @return 1 解锁成功，0 解锁失败
 *  @note  流程：
 *         1. 检查是否已锁定
 *         2. 生成 RSA-OAEP 加密的动态口令
 *         3. 将动态口令编码为 QR 码显示
 *         4. 同时输出 Base64 文本（方便手动复制）
 *         5. 提示输入 8 字符短密钥
 *         6. 验证密钥，成功则进入调试模式
 */
static int psh_cmd_debug(void) {
    /* 检查是否已锁定 */
    if (func_unlock_is_locked()) {
        /* 锁定后 debug 命令无任何输出 */
        return 0;
    }

    /* ===== 生成动态口令 =====
     * R（32 字节）→ RSA-OAEP 公钥加密 → Base64 编码 → 动态口令 */
    char b64_challenge[UNLOCK_B64_CHALLENGE_SIZE];
    if (func_unlock_generate_challenge(b64_challenge, sizeof(b64_challenge)) != 0) {
        fprintf(stderr, "Failed to generate challenge\n");
        return 0;
    }

    /* 确保 QR 码从新行开始（管道输入时无回显换行，光标可能还在提示符后） */
    // printf("\n");

    /* ===== 显示 QR 码 =====
     * 将动态口令编码为 QR 码，管理员可扫码输入解锁工具 */
    func_qrencode_generate_and_print(b64_challenge);

    /* ===== 输出 Base64 文本 =====
     * 同时输出文本格式，方便手动复制 */
    printf("%s\n", b64_challenge);

    /* ===== 提示输入解锁密钥（每次 debug 只允许输入一次） ===== */
    char password[PSH_PWD_MAX_LEN];
    psh_read_password(password, sizeof(password));

    /* ===== 验证密钥 ===== */
    int result = func_unlock_verify(password);

    /* 安全擦除密码 */
    volatile char *vp = (volatile char *)password;
    for (size_t i = 0; i < sizeof(password); i++) {
        vp[i] = 0;
    }

    if (result == 1) {
        /* ===== 解锁成功，进入调试模式 ===== */
        printf("Enter Debug Mode.\n\n");

        /* 打印正常 Shell 横幅 */
        time_t     now = time(NULL);
        struct tm *tm_info = localtime(&now);
        char       time_buf[64];
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S %Z", tm_info);
        printf("BusyBox v1.36.1 (%s) built-in shell (ash)\n\n", time_buf);

        /* 进入调试模式 Shell 循环 */
        while (1) {
            psh_print_prompt();
            char cmd[PSH_CMD_MAX_LEN];
            psh_read_line(cmd, sizeof(cmd));

            /* 空命令跳过 */
            if (cmd[0] == '\0') {
                continue;
            }

            /* exit 命令退出 */
            if (strcmp(cmd, "exit") == 0) {
                break;
            }

            /* 执行系统命令 */
            int ret = system(cmd);
            (void)ret;
        }

        return 1;
    }
    /* result == 0：密钥错误，已由 func_unlock_verify 打印提示，退回 # 提示符 */
    /* result == -1：已锁定，退回 # 提示符，后续 debug 无响应 */
    return 0;
}

/* ========== 公共接口实现 ========== */

void func_psh_run(void) {
    /* 初始化解锁模块 */
    if (func_unlock_init() != 0) {
        fprintf(stderr, "Failed to initialize unlock module\n");
        return;
    }

    /* 打印启动横幅 */
    psh_print_banner();

    /* PSH 主循环：解析并执行受限命令 */
    while (1) {
        psh_print_prompt();

        char cmd[PSH_CMD_MAX_LEN];
        psh_read_line(cmd, sizeof(cmd));

        /* 空命令跳过 */
        if (cmd[0] == '\0') {
            continue;
        }

        /* help 命令 */
        if (strcmp(cmd, "help") == 0) {
            psh_cmd_help();
        }
        /* debug 命令 */
        else if (strcmp(cmd, "debug") == 0) {
            if (psh_cmd_debug()) {
                /* debug 成功解锁后，psh_cmd_debug 内部已处理调试模式 Shell */
                /* 解锁成功后退出 PSH 循环 */
                break;
            }
            /* 解锁失败，继续 PSH 循环 */
            continue;
        }
        /* 不支持的命令 */
        else {
            printf("'%s' Not Supported, Try 'help'\n", cmd);
        }
    }

    /* 清理解锁模块 */
    func_unlock_cleanup();
}
