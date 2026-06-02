/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : func_unlock.c
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 1.0
 * Description: RSA 挑战-应答安全解锁模块实现
 *
 *  基于 mbedtls PSA Crypto API 实现：
 *  - psa_generate_random()     生成 32 字节随机数 R
 *  - psa_generate_key()        生成 RSA 密钥对（OAEP/SHA-256）
 *  - psa_asymmetric_encrypt()  RSA-OAEP 公钥加密
 *  - psa_import_key() +        导入 HMAC 密钥
 *    psa_mac_compute()         计算 HMAC-SHA256
 *
 *  解锁密钥派生流程：
 *    R (32 bytes)
 *      → HMAC-SHA256(key=R, msg="SHELL-UNLOCK")
 *      → 取前 5 字节
 *      → Base64 编码
 *      → 8 字符短密钥（如 "aGJjZGU="）
 * ======================================================
 */

#include "func_unlock.h"
#include "func_base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"

/* ========== 模块内部状态 ========== */

/** PSA Crypto 库初始化标志 */
static int s_psa_initialized = 0;

/** RSA 密钥对 ID（公钥加密 + 私钥解密用） */
static psa_key_id_t s_rsa_key_id = 0;

/** 随机数 R（32 字节，开机时生成一次，重启前不变） */
static uint8_t s_challenge_R[UNLOCK_CHALLENGE_SIZE] = {0};

/** R 是否已生成标志 */
static int s_challenge_ready = 0;

/** 剩余尝试次数 */
static int s_remaining_attempts = UNLOCK_MAX_TRIES;

/* ========== 内部辅助函数 ========== */

/** @fn static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
 *  @brief 恒定时间内存比较，防止时序攻击
 *  @param[in] a   比较缓冲区 A
 *  @param[in] b   比较缓冲区 B
 *  @param[in] len 比较长度
 *  @return 0 相等，-1 不相等
 *  @note  无论是否匹配，执行时间恒定
 */
static int constant_time_compare(const uint8_t *a, const uint8_t *b,
                                 size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0 ? 0 : -1;
}

/** @fn static void secure_erase(void *data, size_t len)
 *  @brief 安全擦除内存中的敏感数据（防止编译器优化删除）
 *  @param[in] data 待擦除的数据指针
 *  @param[in] len  数据长度
 */
static void secure_erase(void *data, size_t len) {
    if (data == NULL) {
        return;
    }
    /* 使用 volatile 指针防止编译器优化掉 memset */
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (len--) {
        *p++ = 0;
    }
}

/* ========== 公共接口实现 ========== */

int func_unlock_init(void) {
    psa_status_t status;

    /* 防止重复初始化 */
    if (s_psa_initialized) {
        return 0;
    }

    /* ===== 步骤 1：初始化 PSA Crypto 库 ===== */
    status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_crypto_init failed: %d\n", status);
        return -1;
    }
    s_psa_initialized = 1;

    /* ===== 步骤 2：生成 32 字节随机数 R =====
     * R 是解锁的核心秘密，在设备开机时生成一次
     * 只要设备不重启，R 不变，派生的短密钥也不变
     * 但每次加密时 OAEP 随机填充不同，所以动态口令每次不同 */
    status = psa_generate_random(s_challenge_R, UNLOCK_CHALLENGE_SIZE);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_generate_random failed: %d\n", status);
        func_unlock_cleanup();
        return -1;
    }
    s_challenge_ready = 1;

    /* ===== 步骤 3：生成 RSA 密钥对 =====
     * 设备端只用公钥加密 R（生成动态口令）
     * 私钥仅在管理端使用（解密动态口令），设备端不保存私钥
     * 此处生成密钥对仅为演示方便，生产环境中应只部署公钥 */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_bits(&attr, UNLOCK_RSA_KEY_BITS);
    psa_set_key_usage_flags(&attr,
                            PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    /* 使用 RSA-OAEP/SHA-256 填充方案，比 PKCS#1 v1.5 更安全 */
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));

    status = psa_generate_key(&attr, &s_rsa_key_id);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_generate_key failed: %d\n", status);
        func_unlock_cleanup();
        return -1;
    }

    /* 重置尝试次数 */
    s_remaining_attempts = UNLOCK_MAX_TRIES;

    return 0;
}

void func_unlock_cleanup(void) {
    /* 安全擦除随机数 R */
    if (s_challenge_ready) {
        secure_erase(s_challenge_R, sizeof(s_challenge_R));
        s_challenge_ready = 0;
    }

    /* 销毁 RSA 密钥 */
    if (s_rsa_key_id != 0) {
        psa_destroy_key(s_rsa_key_id);
        s_rsa_key_id = 0;
    }

    /* 释放 PSA Crypto 库 */
    if (s_psa_initialized) {
        mbedtls_psa_crypto_free();
        s_psa_initialized = 0;
    }

    /* 重置尝试次数 */
    s_remaining_attempts = UNLOCK_MAX_TRIES;
}

int func_unlock_generate_challenge(char *b64_out, size_t b64_size) {
    if (!s_psa_initialized || !s_challenge_ready) {
        fprintf(stderr, "[UNLOCK] not initialized\n");
        return -1;
    }

    if (b64_out == NULL || b64_size == 0) {
        fprintf(stderr, "[UNLOCK] invalid output buffer\n");
        return -1;
    }

    /* ===== RSA-OAEP 公钥加密 R =====
     * 输入：R（32 字节）
     * 输出：密文（UNLOCK_CIPHER_SIZE 字节，RSA-2048 为 256 字节）
     * OAEP 填充保证：即使 R 相同，每次加密结果也不同 */
    uint8_t ciphertext[UNLOCK_CIPHER_SIZE];
    size_t cipher_len = 0;

    psa_status_t status = psa_asymmetric_encrypt(
        s_rsa_key_id,
        PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256),
        s_challenge_R, UNLOCK_CHALLENGE_SIZE,
        NULL, 0, /* OAEP label 为空 */
        ciphertext, sizeof(ciphertext), &cipher_len);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_asymmetric_encrypt failed: %d\n", status);
        return -1;
    }

    /* ===== Base64 编码密文 → 动态口令 =====
     * RSA-2048 密文 256 字节 → Base64 约 344 字符（末尾 "=="）
     * RSA-4096 密文 512 字节 → Base64 约 684 字符（末尾 "="） */
    int b64_len = func_base64_encode(ciphertext, cipher_len, b64_out, b64_size);
    if (b64_len < 0) {
        fprintf(stderr, "[UNLOCK] base64 encode failed\n");
        return -1;
    }

    /* 安全擦除临时密文 */
    secure_erase(ciphertext, sizeof(ciphertext));

    return 0;
}

int func_unlock_derive_short_key(char *key_out, size_t key_size) {
    if (!s_psa_initialized || !s_challenge_ready) {
        fprintf(stderr, "[UNLOCK] not initialized\n");
        return -1;
    }

    if (key_out == NULL || key_size < UNLOCK_SHORT_KEY_B64_SIZE) {
        fprintf(stderr, "[UNLOCK] invalid output buffer\n");
        return -1;
    }

    /* ===== 步骤 1：将 R 作为 HMAC 密钥导入 PSA ===== */
    psa_key_attributes_t hmac_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&hmac_attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&hmac_attr, PSA_BYTES_TO_BITS(UNLOCK_CHALLENGE_SIZE));
    psa_set_key_usage_flags(&hmac_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&hmac_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_key_id_t hmac_key_id = 0;
    psa_status_t status = psa_import_key(&hmac_attr,
                                         s_challenge_R, UNLOCK_CHALLENGE_SIZE,
                                         &hmac_key_id);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_import_key (HMAC) failed: %d\n", status);
        return -1;
    }

    /* ===== 步骤 2：计算 HMAC-SHA256(R, "SHELL-UNLOCK") =====
     * R 作为 HMAC 密钥，"SHELL-UNLOCK" 作为消息
     * 输出 32 字节 MAC 值 */
    uint8_t mac[32];
    size_t mac_len = 0;

    status = psa_mac_compute(hmac_key_id,
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             (const uint8_t *)UNLOCK_HMAC_MSG,
                             strlen(UNLOCK_HMAC_MSG),
                             mac, sizeof(mac), &mac_len);

    /* 用完立即销毁 HMAC 密钥 */
    psa_destroy_key(hmac_key_id);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_mac_compute failed: %d\n", status);
        secure_erase(mac, sizeof(mac));
        return -1;
    }

    /* ===== 步骤 3：取前 5 字节 → Base64 编码 → 8 字符短密钥 =====
     * 5 字节 → Base64 = 8 字符（含 1 个 '=' 填充）
     * 短密钥空间 = 2^40 ≈ 1.1 万亿种可能，配合 5 次限制，暴力破解不可行 */
    int b64_len = func_base64_encode(mac, UNLOCK_SHORT_KEY_BYTES,
                                     key_out, key_size);

    /* 安全擦除 MAC 中间值 */
    secure_erase(mac, sizeof(mac));

    if (b64_len < 0) {
        fprintf(stderr, "[UNLOCK] base64 encode short key failed\n");
        return -1;
    }

    return 0;
}

int func_unlock_verify(const char *user_key) {
    if (!s_psa_initialized || !s_challenge_ready) {
        return -1;
    }

    /* 已锁定，拒绝验证 */
    if (s_remaining_attempts <= 0) {
        return -1;
    }

    /* 检查输入有效性 */
    if (user_key == NULL || strlen(user_key) == 0) {
        printf("input invaild len param\n");
        s_remaining_attempts--;
        printf("Incorrect Password. %d Times Left\n", s_remaining_attempts);
        return 0;
    }

    /* 从 R 派生期望的短密钥 */
    char expected_key[UNLOCK_SHORT_KEY_B64_SIZE];
    if (func_unlock_derive_short_key(expected_key, sizeof(expected_key)) != 0) {
        return -1;
    }

    /* 恒定时间比较，防止时序攻击 */
    int result = constant_time_compare(
        (const uint8_t *)user_key,
        (const uint8_t *)expected_key,
        strlen(expected_key));

    /* 安全擦除期望密钥 */
    secure_erase(expected_key, sizeof(expected_key));

    if (result == 0) {
        /* 验证通过，擦除 R 防止冷启动攻击 */
        secure_erase(s_challenge_R, sizeof(s_challenge_R));
        s_challenge_ready = 0;
        return 1;
    }

    /* 验证失败 */
    s_remaining_attempts--;
    printf("Incorrect Password. %d Times Left\n", s_remaining_attempts);
    return 0;
}

int func_unlock_get_remaining_attempts(void) {
    return s_remaining_attempts;
}

int func_unlock_is_locked(void) {
    return s_remaining_attempts <= 0 ? 1 : 0;
}
