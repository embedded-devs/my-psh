/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : func_rsa.c
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 1.0
 * Description: 基于 mbedtls PSA Crypto API 的 RSA 公钥加密/私钥解密功能封装
 *
 *  RSA 密钥生成与加解密流程：
 *  1. psa_crypto_init()          — 初始化 PSA Crypto 库
 *  2. psa_set_key_type()         — 设置密钥类型为 RSA 密钥对
 *  3. psa_set_key_bits()         — 设置密钥位数（如 2048）
 *  4. psa_set_key_usage_flags()  — 设置密钥使用权限（加密 + 解密）
 *  5. psa_set_key_algorithm()    — 设置填充算法（PKCS#1 v1.5）
 *  6. psa_generate_key()         — 生成 RSA 密钥对，返回 key_id 句柄
 *  7. psa_asymmetric_encrypt()   — 使用公钥加密（对密钥对自动取公钥部分）
 *  8. psa_asymmetric_decrypt()   — 使用私钥解密（对密钥对自动取私钥部分）
 *  9. psa_destroy_key()          — 销毁密钥，释放资源
 * 10. mbedtls_psa_crypto_free()  — 释放 PSA Crypto 库
 *
 *  密钥生成原理：
 *  - 随机生成两个大素数 p、q（各约 key_bits/2 位）
 *  - 计算模数 n = p × q
 *  - 计算欧拉函数 φ(n) = (p-1)(q-1)
 *  - 选择公钥指数 e = 65537（0x10001，最常用的固定值）
 *  - 计算私钥指数 d = e⁻¹ mod φ(n)
 *  - 公钥 = (n, e)，私钥 = (n, d)
 *
 *  注意事项：
 *  - 密钥仅存在于内存中（PSA volatile storage），程序退出后消失
 *  - key_id 是 PSA 密钥存储中的句柄，不是密钥数据本身
 *  - RSA-2048 PKCS#1 v1.5 最大明文长度 = 256 - 11 = 245 字节
 *  - RSA-4096 PKCS#1 v1.5 最大明文长度 = 512 - 11 = 501 字节
 * ======================================================
 */

#include "func_rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"

/* PSA Crypto 库初始化标志，0 表示未初始化，1 表示已初始化 */
static int g_psa_initialized = 0;

/** @fn int func_rsa_init(void)
 *  @brief 初始化 PSA Crypto 库，使用 RSA 功能前必须调用
 *  @return 0 成功，-1 失败
 *  @note  该函数内部有防重复初始化保护，多次调用安全
 */
int func_rsa_init(void) {
    /* 防止重复初始化 */
    if (g_psa_initialized) {
        return 0;
    }

    /* 调用 PSA Crypto 初始化函数，必须在所有 PSA 操作之前调用 */
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[RSA] psa_crypto_init failed: %d\n", status);
        return -1;
    }

    g_psa_initialized = 1;
    return 0;
}

/** @fn void func_rsa_free(void)
 *  @brief 释放 PSA Crypto 库资源，程序退出前调用
 *  @note  释放后所有 key_id 将失效，不可再用于加解密
 */
void func_rsa_free(void) {
    if (g_psa_initialized) {
        /* 释放 PSA Crypto 库内部所有资源（密钥槽、熵池等） */
        mbedtls_psa_crypto_free();
        g_psa_initialized = 0;
    }
}

/** @fn int func_rsa_generate_key(uint32_t key_bits, uint32_t *key_id)
 *  @brief 生成 RSA 密钥对（公钥 + 私钥）
 *  @param[in]  key_bits 密钥位数，推荐 2048 或 4096
 *  @param[out] key_id   输出参数，生成的密钥 ID（PSA 句柄）
 *  @return 0 成功，-1 失败
 *  @note  调用前需先调用 func_rsa_init() 初始化
 *         生成的密钥存储在 PSA volatile storage 中，程序退出后消失
 */
int func_rsa_generate_key(uint32_t key_bits, uint32_t *key_id) {
    if (!g_psa_initialized) {
        fprintf(stderr, "[RSA] PSA Crypto not initialized\n");
        return -1;
    }

    /* 初始化密钥属性结构体，使用 PSA_KEY_ATTRIBUTES_INIT 宏清零 */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    /* 设置密钥类型为 RSA 密钥对（包含公钥和私钥） */
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);

    /* 设置密钥位数，如 2048（约 256 字节模数）或 4096（约 512 字节模数） */
    psa_set_key_bits(&attr, key_bits);

    /* 设置密钥使用权限：允许加密（公钥操作）和解密（私钥操作） */
    psa_set_key_usage_flags(&attr,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);

    /* 设置填充算法为 RSA PKCS#1 v1.5
     * PKCS#1 v1.5 是最常用的 RSA 加密填充方案，兼容性最好
     * 也可以使用 PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256) 获得更强的安全性 */
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_PKCS1V15_CRYPT);

    /* 生成 RSA 密钥对
     * 内部流程：随机生成两个大素数 p、q，计算 n=p*q，选择 e=65537，计算 d
     * 生成的密钥通过 key_id 句柄访问，密钥数据本身不暴露给调用者 */
    psa_status_t status = psa_generate_key(&attr, (psa_key_id_t *)key_id);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[RSA] psa_generate_key failed: %d\n", status);
        return -1;
    }

    return 0;
}

/** @fn int func_rsa_encrypt(uint32_t key_id, const uint8_t *plaintext, size_t plaintext_len, uint8_t *ciphertext, size_t cipher_size, size_t *cipher_len)
 *  @brief 使用公钥加密数据（RSA PKCS#1 v1.5）
 *  @param[in]  key_id        RSA 密钥对 ID（由 func_rsa_generate_key 生成）
 *  @param[in]  plaintext     明文数据
 *  @param[in]  plaintext_len 明文长度（字节）
 *  @param[out] ciphertext    输出密文缓冲区
 *  @param[in]  cipher_size   密文缓冲区大小（RSA-2048 需至少 256 字节）
 *  @param[out] cipher_len    输出参数，实际密文长度
 *  @return 0 成功，-1 失败
 *  @note  RSA-2048 最大明文长度 = 256 - 11 = 245 字节（PKCS#1 v1.5 填充占用 11 字节）
 *         RSA-4096 最大明文长度 = 512 - 11 = 501 字节
 *         对 RSA_KEY_PAIR 类型密钥，psa_asymmetric_encrypt 自动使用公钥部分加密
 */
int func_rsa_encrypt(uint32_t key_id,
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t cipher_size,
                     size_t *cipher_len) {
    if (!g_psa_initialized) {
        fprintf(stderr, "[RSA] PSA Crypto not initialized\n");
        return -1;
    }

    /* 调用 PSA 非对称加密接口
     * - key_id:       密钥句柄（对密钥对类型自动取公钥加密）
     * - alg:          加密算法，必须与生成密钥时设置的算法一致
     * - plaintext:    明文数据及长度
     * - NULL, 0:      salt/label，PKCS#1 v1.5 不需要，OAEP 时可传入 label
     * - ciphertext:   密文输出缓冲区及大小
     * - cipher_len:   实际写入的密文长度 */
    psa_status_t status = psa_asymmetric_encrypt(
        (psa_key_id_t)key_id, PSA_ALG_RSA_PKCS1V15_CRYPT,
        plaintext, plaintext_len,
        NULL, 0,
        ciphertext, cipher_size, cipher_len);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[RSA] psa_asymmetric_encrypt failed: %d\n", status);
        return -1;
    }

    return 0;
}

/** @fn int func_rsa_decrypt(uint32_t key_id, const uint8_t *ciphertext, size_t cipher_len, uint8_t *plaintext, size_t plain_size, size_t *plain_len)
 *  @brief 使用私钥解密数据（RSA PKCS#1 v1.5）
 *  @param[in]  key_id        RSA 密钥对 ID（需要私钥权限）
 *  @param[in]  ciphertext    密文数据
 *  @param[in]  cipher_len    密文长度
 *  @param[out] plaintext     输出明文缓冲区
 *  @param[in]  plain_size    明文缓冲区大小
 *  @param[out] plain_len     输出参数，实际明文长度
 *  @return 0 成功，-1 失败
 *  @note  解密算法必须与加密时一致（PKCS#1 v1.5）
 *         密钥必须具有 PSA_KEY_USAGE_DECRYPT 权限
 */
int func_rsa_decrypt(uint32_t key_id,
                     const uint8_t *ciphertext, size_t cipher_len,
                     uint8_t *plaintext, size_t plain_size,
                     size_t *plain_len) {
    if (!g_psa_initialized) {
        fprintf(stderr, "[RSA] PSA Crypto not initialized\n");
        return -1;
    }

    /* 调用 PSA 非对称解密接口
     * - key_id:       密钥句柄（对密钥对类型自动取私钥解密）
     * - alg:          解密算法，必须与加密时一致
     * - ciphertext:   密文数据及长度
     * - NULL, 0:      salt/label，必须与加密时传入的一致
     * - plaintext:    明文输出缓冲区及大小
     * - plain_len:    实际解密出的明文长度 */
    psa_status_t status = psa_asymmetric_decrypt(
        (psa_key_id_t)key_id, PSA_ALG_RSA_PKCS1V15_CRYPT,
        ciphertext, cipher_len,
        NULL, 0,
        plaintext, plain_size, plain_len);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[RSA] psa_asymmetric_decrypt failed: %d\n", status);
        return -1;
    }

    return 0;
}

/** @fn void func_rsa_destroy_key(uint32_t key_id)
 *  @brief 销毁 RSA 密钥，释放 PSA 密钥槽资源
 *  @param[in] key_id 要销毁的密钥 ID
 *  @note  销毁后该 key_id 不可再用于加解密操作
 */
void func_rsa_destroy_key(uint32_t key_id) {
    /* 从 PSA 密钥存储中移除密钥，释放占用的密钥槽 */
    psa_destroy_key((psa_key_id_t)key_id);
}

/* ========== 辅助函数：十六进制打印 ========== */

/** @fn static void print_hex(const char *label, const uint8_t *data, size_t len)
 *  @brief 以十六进制格式打印字节数组，用于调试输出
 *  @param[in] label 打印标签前缀
 *  @param[in] data  待打印的数据
 *  @param[in] len   数据长度
 *  @note  超过 64 字节时只显示前后各 16 字节，中间用省略号代替
 */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s (", label);
    if (len <= 64) {
        /* 短数据：完整打印 */
        for (size_t i = 0; i < len; i++) {
            printf("%02X", data[i]);
        }
    } else {
        /* 长数据：只打印前 16 字节 + 省略 + 后 16 字节 */
        for (size_t i = 0; i < 16; i++) {
            printf("%02X", data[i]);
        }
        printf("...(%zu bytes)...", len);
        for (size_t i = len - 16; i < len; i++) {
            printf("%02X", data[i]);
        }
    }
    printf(")\n");
}

/** @fn void func_rsa_test(void)
 *  @brief RSA 公钥加密/私钥解密 自测函数
 *  @note  完整流程：初始化 → 生成密钥 → 加密 → 解密 → 验证 → 清理
 */
void func_rsa_test(void) {
    printf("\n========== RSA 加解密测试 ==========\n");

    /* ===== 第 1 步：初始化 PSA Crypto 库 ===== */
    if (func_rsa_init() != 0) {
        fprintf(stderr, "[TEST] RSA init failed\n");
        return;
    }

    /* ===== 第 2 步：生成 2048 位 RSA 密钥对 =====
     * RSA-2048 是目前最常用的密钥长度，安全性与性能均衡
     * 生成过程：随机选取两个约 1024 位的大素数 p、q
     *         计算模数 n=p*q，公钥指数 e=65537，私钥指数 d=e⁻¹ mod φ(n)
     */
    uint32_t key_id = 0;
    printf("[TEST] Generating RSA-2048 key pair...\n");
    if (func_rsa_generate_key(2048, &key_id) != 0) {
        fprintf(stderr, "[TEST] Key generation failed\n");
        func_rsa_free();
        return;
    }
    printf("[TEST] Key generated, key_id = %u\n", key_id);

    /* ===== 第 3 步：准备待加密的明文 ===== */
    const char *message = "Hello, RSA! mbedtls PSA crypto test.";
    size_t msg_len = strlen(message);
    printf("[TEST] Plaintext: \"%s\" (%zu bytes)\n", message, msg_len);

    /* ===== 第 4 步：使用公钥加密 =====
     * RSA-2048 PKCS#1 v1.5 密文固定为 256 字节（等于密钥模数长度）
     * 明文最大长度 = 密钥字节数 - 填充开销 = 256 - 11 = 245 字节
     */
    uint8_t ciphertext[256];
    size_t cipher_len = 0;

    printf("[TEST] Encrypting with public key...\n");
    if (func_rsa_encrypt(key_id,
                         (const uint8_t *)message, msg_len,
                         ciphertext, sizeof(ciphertext), &cipher_len) != 0) {
        fprintf(stderr, "[TEST] Encryption failed\n");
        func_rsa_destroy_key(key_id);
        func_rsa_free();
        return;
    }
    printf("[TEST] Encrypted, ciphertext length: %zu bytes\n", cipher_len);
    print_hex("[TEST] Ciphertext", ciphertext, cipher_len);

    /* ===== 第 5 步：使用私钥解密 =====
     * 解密时密钥对会自动使用私钥部分进行解密
     * 解密后的明文长度应与原始明文长度一致
     */
    uint8_t decrypted[512];
    size_t dec_len = 0;

    printf("[TEST] Decrypting with private key...\n");
    if (func_rsa_decrypt(key_id,
                         ciphertext, cipher_len,
                         decrypted, sizeof(decrypted), &dec_len) != 0) {
        fprintf(stderr, "[TEST] Decryption failed\n");
        func_rsa_destroy_key(key_id);
        func_rsa_free();
        return;
    }

    /* ===== 第 6 步：验证加解密结果 =====
     * 比较解密后的数据与原始明文是否完全一致
     */
    decrypted[dec_len] = '\0';
    printf("[TEST] Decrypted: \"%s\" (%zu bytes)\n", decrypted, dec_len);

    if (dec_len == msg_len && memcmp(message, decrypted, msg_len) == 0) {
        printf("[TEST] ✅ RSA encrypt/decrypt PASSED!\n");
    } else {
        printf("[TEST] ❌ RSA encrypt/decrypt FAILED!\n");
    }

    /* ===== 第 7 步：清理资源 =====
     * 先销毁密钥（释放密钥槽），再释放 PSA Crypto 库
     */
    func_rsa_destroy_key(key_id);
    func_rsa_free();

    printf("========== RSA 测试结束 ==========\n\n");
}
