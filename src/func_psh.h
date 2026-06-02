/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : func_psh.h
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 1.0
 * Description: PSH（Protect Shell）受保护 Shell 模块
 *
 *  PSH 是设备的受限 Shell 环境：
 *  - 仅支持 help、debug 两条命令
 *  - debug 命令生成 RSA 挑战码（动态口令），显示为 QR 码 + Base64 文本
 *  - 用户输入正确的 8 字符短密钥后，进入调试模式（正常 Shell）
 *  - 超过最大尝试次数后锁定，需重启设备
 * ======================================================
 */

#ifndef FUNC_PSH_H
#define FUNC_PSH_H

#ifdef __cplusplus
extern "C" {
#endif

/** 最大命令行长度 */
#define PSH_QRCODE_ENA  0

/** @fn void func_psh_run(void)
 *  @brief 运行 PSH 受保护 Shell 主循环
 *  @note  该函数会阻塞直到用户解锁进入调试模式或退出
 *         流程：显示版本信息 → 等待命令输入 → 处理命令 → 解锁后进入调试模式
 */
void func_psh_run(void);

#ifdef __cplusplus
}
#endif

#endif /* FUNC_PSH_H */
