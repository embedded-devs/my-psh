/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : main.c
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 1.0
 * Description: PSH（Protect Shell）主入口
 *
 *  程序启动后进入 PSH 受限 Shell，仅支持 help 和 debug 命令。
 *  通过 debug 命令生成 RSA 挑战码，输入正确短密钥后进入调试模式。
 * ======================================================
 */
#include "src/func_psh.h"

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    /* 运行 PSH 受保护 Shell */
    func_psh_run();

    return 0;
}
