/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : func_unlock.h
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 1.0
 * Description: RSA 挑战-应答安全解锁模块
 *
 *  解锁流程：
 *  1. 设备开机后生成 32 字节随机数 R（一次生成，重启前不变）
 *  2. 用户输入 debug 命令时，用 RSA-OAEP 公钥加密 R → 加版本前缀 → Base64 编码 → 生成动态口令
 *  3. 管理员在远程用私钥解密得到 R，再派生 8 字符短密钥（无 '=' 填充）
 *  4. 用户输入短密钥，设备验证后进入调试模式
 *
 *  安全特性：
 *  - 设备仅持有公钥，物理窃取无法自行解锁
 *  - RSA-OAEP 填充保证同一明文每次加密结果不同（动态口令每次不同）
 *  - 短密钥由 R 派生，R 不变则短密钥不变
 *  - 恒定时间比较，防止时序攻击
 *  - 验证后从内存擦除敏感数据
 * ======================================================
 */

#ifndef FUNC_UNLOCK_H
#define FUNC_UNLOCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** 随机数 R 的长度（字节） */
#define UNLOCK_CHALLENGE_SIZE       32

/** RSA 密钥位数（默认 2048，生产环境建议 4096） */
#define UNLOCK_RSA_KEY_BITS         2048

/** RSA 密文长度（字节），等于密钥字节数 = key_bits / 8 */
#define UNLOCK_CIPHER_SIZE          (UNLOCK_RSA_KEY_BITS / 8)

/** 密文版本前缀长度（1 字节），使 1+256=257 字节，257%3=2 → Base64 仅有 1 个 '=' */
#define UNLOCK_CIPHER_PREFIX_SIZE   1

/** 密文版本前缀值（0x00），预留未来协议扩展 */
#define UNLOCK_CIPHER_PREFIX_VER    0x00

/** Base64 编码后动态口令最大长度（含结尾 '\0'）
 *  密文前加 1 字节版本前缀：1 + 256 = 257 字节，257%3=2 → Base64 末尾 1 个 '='
 */
#define UNLOCK_B64_CHALLENGE_SIZE   ((UNLOCK_CIPHER_SIZE + UNLOCK_CIPHER_PREFIX_SIZE + 2) / 3 * 4 + 1)

/** 短密钥原始字节数（HMAC-SHA256 前 6 字节，6%3=0 → Base64 无 '=' 填充） */
#define UNLOCK_SHORT_KEY_BYTES      6

/** 短密钥 Base64 编码后长度（6字节 → 8字符，无 '=' 填充，含结尾 '\0'） */
#define UNLOCK_SHORT_KEY_B64_SIZE   9

/** 最大尝试次数 */
#define UNLOCK_MAX_TRIES            5

/** HMAC 消息常量 */
#define UNLOCK_HMAC_MSG             "SHELL-UNLOCK"

/** 公钥 PEM 文件默认路径（相对运行目录） */
#define UNLOCK_PUBKEY_PATH          "keys/public_key.pem"

/** DER 编码公钥最大缓冲区大小（足够 RSA-4096） */
#define PUBKEY_DER_MAX_SIZE         2048

/** @fn int func_unlock_init(void)
 *  @brief 初始化解锁模块：初始化 PSA Crypto，生成随机数 R，加载 RSA 公钥
 *  @return 0 成功，-1 失败
 *  @note  R 在初始化时生成一次，重启前不变，因此短密钥也不变
 *         公钥从 UNLOCK_PUBKEY_PATH 指定的 PEM 文件加载，
 *         可通过环境变量 UNLOCK_PUBKEY_PATH 覆盖默认路径
 */
int func_unlock_init(void);

/** @fn void func_unlock_cleanup(void)
 *  @brief 清理解锁模块：安全擦除 R，销毁密钥，释放 PSA Crypto 资源
 *  @note  验证完成后应立即调用，擦除内存中的敏感数据
 */
void func_unlock_cleanup(void);

/** @fn int func_unlock_generate_challenge(char *b64_out, size_t b64_size)
 *  @brief 生成动态口令：用 RSA-OAEP 公钥加密 R，然后 Base64 编码
 *  @param[out] b64_out  输出 Base64 编码的动态口令字符串
 *  @param[in]  b64_size 输出缓冲区大小（建议 UNLOCK_B64_CHALLENGE_SIZE）
 *  @return 0 成功，-1 失败
 *  @note  由于 OAEP 随机填充，每次调用产生不同的密文和动态口令
 */
int func_unlock_generate_challenge(char *b64_out, size_t b64_size);

/** @fn int func_unlock_derive_short_key(char *key_out, size_t key_size)
 *  @brief 从 R 派生 8 字符短密钥（管理端模拟）
 *  @param[out] key_out  输出短密钥字符串（如 "aGJjZGVm"，无 '=' 填充）
 *  @param[in]  key_size 输出缓冲区大小（至少 UNLOCK_SHORT_KEY_B64_SIZE）
 *  @return 0 成功，-1 失败
 *  @note  派生算法：HMAC-SHA256(R, "SHELL-UNLOCK") 取前 6 字节 → Base64 编码
 *         此函数仅供管理端模拟测试，实际设备端不暴露此接口
 */
int func_unlock_derive_short_key(char *key_out, size_t key_size);

/** @fn int func_unlock_verify(const char *user_key)
 *  @brief 验证用户输入的短密钥是否正确
 *  @param[in] user_key 用户输入的短密钥字符串
 *  @return 1 验证通过，0 验证失败（密钥不匹配），-1 已锁定/错误
 *  @note  使用恒定时间比较防止时序攻击
 *         超过最大尝试次数后锁定，返回 -1
 */
int func_unlock_verify(const char *user_key);

/** @fn int func_unlock_get_remaining_attempts(void)
 *  @brief 获取剩余尝试次数
 *  @return 剩余次数（0 表示已锁定）
 */
int func_unlock_get_remaining_attempts(void);

/** @fn int func_unlock_is_locked(void)
 *  @brief 检查是否已锁定（尝试次数耗尽）
 *  @return 1 已锁定，0 未锁定
 */
int func_unlock_is_locked(void);

#ifdef __cplusplus
}
#endif

#endif /* FUNC_UNLOCK_H */
