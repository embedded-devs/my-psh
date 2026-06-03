/** =====================================================
 * Copyright © sumu. 2022-present. Tech. Co., Ltd. All rights reserved.
 * File name  : func_unlock.c
 * Author     : sumu
 * Date       : 2025/06/02
 * Version    : 2.0
 * Description: RSA 挑战-应答安全解锁模块实现
 *
 *  基于 mbedtls PSA Crypto API 实现：
 *  - psa_generate_random()     生成 32 字节随机数 R
 *  - mbedtls_pk_parse_public_key()  从 PEM 文件加载 RSA 公钥
 *  - psa_import_key()          导入 RSA 公钥到 PSA
 *  - psa_asymmetric_encrypt()  RSA-OAEP 公钥加密
 *  - psa_import_key() +        导入 HMAC 密钥
 *    psa_mac_compute()         计算 HMAC-SHA256
 *
 *  解锁密钥派生流程：
 *    R (32 bytes)
 *      → HMAC-SHA256(key=R, msg="SHELL-UNLOCK")
 *      → 取前 6 字节
 *      → Base64 编码
 *      → 8 字符短密钥（如 "aGJjZGVm"，无 '=' 填充）
 *
 *  密钥管理：
 *    - 设备端只持有 RSA 公钥（从 PEM 文件加载）
 *    - 私钥由管理员离线保管，不在设备端存储
 *    - 公钥文件由 keys/gen_keys.sh 生成
 *    - 管理员使用 keys/unlock.sh 解密动态口令
 * ======================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "psa/crypto.h"
#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"

#include "func_unlock.h"
#include "func_base64.h"

/* ========== 模块内部状态 ========== */

/** PSA Crypto 库初始化标志 */
static int s_psa_initialized = 0;

/** RSA 公钥 ID（仅用于公钥加密） */
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
static int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
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

/** @fn static int load_public_key_from_pem(const char *pem_path, psa_key_id_t *key_id)
 *  @brief 从 PEM 文件加载 RSA 公钥到 PSA 密钥槽
 *  @param[in]  pem_path 公钥 PEM 文件路径
 *  @param[out] key_id   输出 PSA 密钥 ID
 *  @return 0 成功，-1 失败
 *  @note  流程：读取 PEM → mbedtls_pk 解析 → 导出 DER → psa_import_key 导入
 */
static int load_public_key_from_pem(const char *pem_path, psa_key_id_t *key_id) {
    int                ret = -1;
    FILE              *fp = NULL;
    long               file_size = 0;
    uint8_t           *pem_buf = NULL;
    uint8_t           *der_buf = NULL;
    mbedtls_pk_context pk;

    /* ===== 1. 读取 PEM 文件 ===== */
    fp = fopen(pem_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[UNLOCK] Cannot open public key: %s\n", pem_path);
        fprintf(stderr, "[UNLOCK] Please run: keys/gen_keys.sh\n");
        return -1;
    }

    /* 获取文件大小 */
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fprintf(stderr, "[UNLOCK] Invalid public key file size\n");
        fclose(fp);
        return -1;
    }

    /* 分配缓冲区：+1 用于末尾 '\0' 终止符（mbedtls 解析需要） */
    pem_buf = (uint8_t *)malloc((size_t)file_size + 1);
    if (pem_buf == NULL) {
        fprintf(stderr, "[UNLOCK] malloc failed\n");
        fclose(fp);
        return -1;
    }

    if (fread(pem_buf, 1, (size_t)file_size, fp) != (size_t)file_size) {
        fprintf(stderr, "[UNLOCK] fread failed\n");
        fclose(fp);
        free(pem_buf);
        return -1;
    }
    pem_buf[file_size] = '\0'; /* mbedtls_pk_parse_public_key 需要 NULL 终止 */
    fclose(fp);

    /* ===== 2. 解析 PEM 格式公钥 ===== */
    mbedtls_pk_init(&pk);
    ret = mbedtls_pk_parse_public_key(&pk, pem_buf, (size_t)file_size + 1);
    if (ret != 0) {
        fprintf(stderr, "[UNLOCK] mbedtls_pk_parse_public_key failed: -0x%04x\n", (unsigned int)-ret);
        mbedtls_pk_free(&pk);
        secure_erase(pem_buf, (size_t)file_size + 1);
        free(pem_buf);
        return -1;
    }

    /* 注意: mbedTLS 4.0.0 不再提供 mbedtls_pk_get_type() 接口
     * 密钥类型验证由后续 psa_import_key() 保证:
     * 非 RSA 密钥导入时 psa_import_key() 会返回 PSA_ERROR_INVALID_ARGUMENT */

    /* ===== 3. 导出 DER 格式 ===== */
    der_buf = (uint8_t *)malloc(PUBKEY_DER_MAX_SIZE);
    if (der_buf == NULL) {
        fprintf(stderr, "[UNLOCK] malloc failed\n");
        mbedtls_pk_free(&pk);
        secure_erase(pem_buf, (size_t)file_size + 1);
        free(pem_buf);
        return -1;
    }

    int der_len = mbedtls_pk_write_pubkey_der(&pk, der_buf, PUBKEY_DER_MAX_SIZE);
    mbedtls_pk_free(&pk);

    if (der_len < 0) {
        fprintf(stderr, "[UNLOCK] mbedtls_pk_write_pubkey_der failed: -0x%04x\n", (unsigned int)-der_len);
        secure_erase(der_buf, PUBKEY_DER_MAX_SIZE);
        free(der_buf);
        secure_erase(pem_buf, (size_t)file_size + 1);
        free(pem_buf);
        return -1;
    }

    /* mbedtls_pk_write_pubkey_der 从缓冲区末尾开始写入 */
    uint8_t *der_start = der_buf + PUBKEY_DER_MAX_SIZE - der_len;

    /* ===== 3b. 从 SubjectPublicKeyInfo 中提取 RSAPublicKey =====
     * mbedtls_pk_write_pubkey_der 输出 SubjectPublicKeyInfo 格式:
     *   SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
     * psa_import_key(PSA_KEY_TYPE_RSA_PUBLIC_KEY) 期望 PKCS#1 RSAPublicKey 格式
     * 因此需要解析 ASN.1 提取 BIT STRING 中的 RSAPublicKey */
    uint8_t *rsa_pubkey = NULL;
    size_t   rsa_pubkey_len = 0;
    {
        uint8_t *p = der_start;
        uint8_t *end = der_start + der_len;
        size_t   seq_len = 0;

        /* 解析外层 SEQUENCE 标签 */
        int ret2 = mbedtls_asn1_get_tag(&p, end, &seq_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret2 != 0) {
            fprintf(stderr, "[UNLOCK] ASN1: failed to parse outer SEQUENCE: -0x%04x\n", (unsigned int)-ret2);
            secure_erase(der_buf, PUBKEY_DER_MAX_SIZE);
            free(der_buf);
            secure_erase(pem_buf, (size_t)file_size + 1);
            free(pem_buf);
            return -1;
        }

        /* 解析并跳过 AlgorithmIdentifier（包含 OID 和可选参数） */
        mbedtls_asn1_buf alg_oid;
        mbedtls_asn1_buf alg_params;
        ret2 = mbedtls_asn1_get_alg(&p, end, &alg_oid, &alg_params);
        if (ret2 != 0) {
            fprintf(stderr, "[UNLOCK] ASN1: failed to parse AlgorithmIdentifier: -0x%04x\n", (unsigned int)-ret2);
            secure_erase(der_buf, PUBKEY_DER_MAX_SIZE);
            free(der_buf);
            secure_erase(pem_buf, (size_t)file_size + 1);
            free(pem_buf);
            return -1;
        }

        /* 解析 BIT STRING，其内容即为 PKCS#1 格式的 RSAPublicKey */
        mbedtls_asn1_bitstring bs;
        memset(&bs, 0, sizeof(bs));
        ret2 = mbedtls_asn1_get_bitstring(&p, end, &bs);
        if (ret2 != 0) {
            fprintf(stderr, "[UNLOCK] ASN1: failed to parse BIT STRING: -0x%04x\n", (unsigned int)-ret2);
            secure_erase(der_buf, PUBKEY_DER_MAX_SIZE);
            free(der_buf);
            secure_erase(pem_buf, (size_t)file_size + 1);
            free(pem_buf);
            return -1;
        }

        /* bs.p 指向 RSAPublicKey 的 DER 编码，bs.len 为字节长度 */
        rsa_pubkey = bs.p;
        rsa_pubkey_len = bs.len;
    }

    /* ===== 4. 导入 PSA 密钥槽 =====
     * 设置密钥属性：
     *   - 类型：RSA 公钥
     *   - 用途：仅允许加密（PSA_KEY_USAGE_ENCRYPT）
     *   - 算法：RSA-OAEP with SHA-256
     * 导入后 key_id 可用于 psa_asymmetric_encrypt() */
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256));

    psa_status_t status = psa_import_key(&attr, rsa_pubkey, rsa_pubkey_len, key_id);

    /* 安全擦除临时缓冲区 */
    secure_erase(der_buf, PUBKEY_DER_MAX_SIZE);
    free(der_buf);
    secure_erase(pem_buf, (size_t)file_size + 1);
    free(pem_buf);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_import_key failed: %d\n", (int)status);
        return -1;
    }

    return 0;
}

/* ========== 公共接口实现 ========== */

/** @fn int func_unlock_init(void)
 *  @brief 初始化解锁模块（PSA Crypto + 生成随机数 R + 加载 RSA 公钥）
 *  @return 0 成功，-1 失败
 *  @note  初始化流程：
 *         1. 初始化 PSA Crypto 库（仅首次有效，防重复初始化）
 *         2. 生成 32 字节密码学安全随机数 R（开机一次，重启前不变）
 *         3. 从 PEM 文件加载 RSA 公钥到 PSA 密钥槽
 *         4. 重置尝试次数为最大值
 */
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

    /* ===== 步骤 3：从 PEM 文件加载 RSA 公钥 =====
     * 设备端只持有公钥，用于加密 R 生成动态口令
     * 私钥仅在管理端使用（解密动态口令），设备端不保存私钥
     * 公钥文件由 keys/gen_keys.sh 脚本生成
     * 可通过环境变量 UNLOCK_PUBKEY_PATH 覆盖默认路径 */
    const char *pubkey_path = getenv("UNLOCK_PUBKEY_PATH");
    if (pubkey_path == NULL || pubkey_path[0] == '\0') {
        pubkey_path = UNLOCK_PUBKEY_PATH;
    }

    if (load_public_key_from_pem(pubkey_path, &s_rsa_key_id) != 0) {
        func_unlock_cleanup();
        return -1;
    }

    /* 重置尝试次数 */
    s_remaining_attempts = UNLOCK_MAX_TRIES;

    return 0;
}

/** @fn void func_unlock_cleanup(void)
 *  @brief 清理解锁模块，安全擦除所有敏感数据并释放资源
 *  @note  清理顺序：
 *         1. 安全擦除随机数 R（防冷启动攻击）
 *         2. 销毁 PSA RSA 密钥
 *         3. 释放 PSA Crypto 库
 *         4. 重置尝试次数
 */
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

/** @fn int func_unlock_generate_challenge(char *b64_out, size_t b64_size)
 *  @brief 生成动态口令：用 RSA-OAEP 公钥加密 R，然后 Base64 编码输出
 *  @param[out] b64_out  输出 Base64 编码的动态口令字符串缓冲区
 *  @param[in]  b64_size 输出缓冲区大小（建议 UNLOCK_B64_CHALLENGE_SIZE）
 *  @return 0 成功，-1 失败
 *  @note  流程：
 *         1. 用 RSA-OAEP(SHA-256) 公钥加密 R → 密文（256 字节）
 *         2. 在密文前拼接 1 字节版本前缀 → 257 字节
 *         3. Base64 编码 → 约 344 字符动态口令
 *         OAEP 填充保证：即使 R 相同，每次加密结果也不同
 */
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
    size_t  cipher_len = 0;

    psa_status_t status = psa_asymmetric_encrypt(s_rsa_key_id, PSA_ALG_RSA_OAEP(PSA_ALG_SHA_256), s_challenge_R,
                                                 UNLOCK_CHALLENGE_SIZE, NULL, 0, /* OAEP label 为空 */
                                                 ciphertext, sizeof(ciphertext), &cipher_len);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_asymmetric_encrypt failed: %d\n", status);
        return -1;
    }

    /* ===== 拼接版本前缀 + 密文 =====
     * 在密文前加 1 字节版本前缀，使总长 257 字节 (257%3=2 → Base64 仅 1 个 '=')
     * 解码时需跳过首字节再进行 RSA 解密 */
    uint8_t prefixed[UNLOCK_CIPHER_PREFIX_SIZE + UNLOCK_CIPHER_SIZE];
    prefixed[0] = UNLOCK_CIPHER_PREFIX_VER;
    memcpy(prefixed + UNLOCK_CIPHER_PREFIX_SIZE, ciphertext, cipher_len);

    /* ===== Base64 编码（版本前缀 + 密文）→ 动态口令 =====
     * 257 字节 → Base64 约 344 字符（末尾 "="）
     * 对比原 256 字节 → Base64 约 344 字符（末尾 "=="） */
    int b64_len = func_base64_encode(prefixed, UNLOCK_CIPHER_PREFIX_SIZE + cipher_len, b64_out, b64_size);
    if (b64_len < 0) {
        fprintf(stderr, "[UNLOCK] base64 encode failed\n");
        return -1;
    }

    /* 安全擦除临时密文和前缀缓冲区 */
    secure_erase(ciphertext, sizeof(ciphertext));
    secure_erase(prefixed, sizeof(prefixed));

    return 0;
}

/** @fn int func_unlock_derive_short_key(char *key_out, size_t key_size)
 *  @brief 从 R 派生 8 字符短密钥（管理端和设备端使用相同算法可得到相同结果）
 *  @param[out] key_out  输出短密钥缓冲区
 *  @param[in]  key_size 缓冲区大小（至少 UNLOCK_SHORT_KEY_B64_SIZE）
 *  @return 0 成功，-1 失败
 *  @note  派生算法：
 *         1. 将 R 作为 HMAC 密钥导入 PSA
 *         2. 计算 HMAC-SHA256(key=R, msg="SHELL-UNLOCK") → 32 字节 MAC
 *         3. 取前 6 字节 → Base64 编码 → 8 字符短密钥（无 '=' 填充）
 *         短密钥空间 = 2^48 ≈ 2.8 万亿，配合 5 次尝试限制，暴力破解不可行
 */
int func_unlock_derive_short_key(char *key_out, size_t key_size) {
    if (!s_psa_initialized || !s_challenge_ready) {
        fprintf(stderr, "[UNLOCK] not initialized\n");
        return -1;
    }

    if (key_out == NULL || key_size < UNLOCK_SHORT_KEY_B64_SIZE) {
        fprintf(stderr, "[UNLOCK] invalid output buffer\n");
        return -1;
    }

    /* ===== 步骤 1：将 R 作为 HMAC 密钥导入 PSA =====
     * 密钥属性设置：
     *   - 类型：HMAC 对称密钥
     *   - 位宽：32 字节 × 8 = 256 位
     *   - 用途：仅允许签名（PSA_KEY_USAGE_SIGN_MESSAGE）
     *   - 算法：HMAC-SHA256 */
    psa_key_attributes_t hmac_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&hmac_attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&hmac_attr, PSA_BYTES_TO_BITS(UNLOCK_CHALLENGE_SIZE));
    psa_set_key_usage_flags(&hmac_attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&hmac_attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));

    psa_key_id_t hmac_key_id = 0;
    psa_status_t status = psa_import_key(&hmac_attr, s_challenge_R, UNLOCK_CHALLENGE_SIZE, &hmac_key_id);
    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_import_key (HMAC) failed: %d\n", status);
        return -1;
    }

    /* ===== 步骤 2：计算 HMAC-SHA256(R, "SHELL-UNLOCK") =====
     * R 作为 HMAC 密钥，"SHELL-UNLOCK" 作为消息
     * 输出 32 字节 MAC 值 */
    uint8_t mac[32];
    size_t  mac_len = 0;

    status = psa_mac_compute(hmac_key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), (const uint8_t *)UNLOCK_HMAC_MSG,
                             strlen(UNLOCK_HMAC_MSG), mac, sizeof(mac), &mac_len);

    /* 用完立即销毁 HMAC 密钥 */
    psa_destroy_key(hmac_key_id);

    if (status != PSA_SUCCESS) {
        fprintf(stderr, "[UNLOCK] psa_mac_compute failed: %d\n", status);
        secure_erase(mac, sizeof(mac));
        return -1;
    }

    /* ===== 步骤 3：取前 6 字节 → Base64 编码 → 8 字符短密钥 =====
     * 6 字节 → Base64 = 8 字符（6%3=0，无 '=' 填充）
     * 短密钥空间 = 2^48 ≈ 2.8 万亿种可能，配合 5 次限制，暴力破解不可行 */
    int b64_len = func_base64_encode(mac, UNLOCK_SHORT_KEY_BYTES, key_out, key_size);

    /* 安全擦除 MAC 中间值 */
    secure_erase(mac, sizeof(mac));

    if (b64_len < 0) {
        fprintf(stderr, "[UNLOCK] base64 encode short key failed\n");
        return -1;
    }

    return 0;
}

/** @fn int func_unlock_verify(const char *user_key)
 *  @brief 验证用户输入的短密钥是否正确
 *  @param[in] user_key 用户输入的短密钥字符串
 *  @return 1 验证通过，0 验证失败（密钥错误），-1 已锁定或内部错误
 *  @note  安全措施：
 *         - 使用恒定时间比较防止时序攻击
 *         - 验证通过后立即擦除 R（防止冷启动攻击）
 *         - 每次失败递减剩余尝试次数，耗尽后锁定
 */
int func_unlock_verify(const char *user_key) {
    if (!s_psa_initialized || !s_challenge_ready) {
        return -1;
    }

    /* 已锁定（尝试次数耗尽），拒绝任何验证请求 */
    if (s_remaining_attempts <= 0) {
        return -1;
    }

    /* 检查输入有效性：空指针或空字符串视为无效输入 */
    if (user_key == NULL || strlen(user_key) == 0) {
        printf("input invaild len param\n");
        s_remaining_attempts--;
        printf("Incorrect Password. %d Times Left\n", s_remaining_attempts);
        return 0;
    }

    /* 从 R 派生期望的短密钥（与设备端算法一致） */
    char expected_key[UNLOCK_SHORT_KEY_B64_SIZE];
    if (func_unlock_derive_short_key(expected_key, sizeof(expected_key)) != 0) {
        return -1;
    }

    /* 恒定时间比较，防止通过耗时差异推断密钥内容的时序攻击 */
    int result = constant_time_compare((const uint8_t *)user_key, (const uint8_t *)expected_key, strlen(expected_key));

    /* 立即安全擦除期望密钥，缩短敏感数据在内存中的存活时间 */
    secure_erase(expected_key, sizeof(expected_key));

    if (result == 0) {
        /* 验证通过：立即擦除 R，防止冷启动攻击提取内存中的核心秘密 */
        secure_erase(s_challenge_R, sizeof(s_challenge_R));
        s_challenge_ready = 0;
        return 1;
    }

    /* 验证失败：递减剩余次数，耗尽后锁定（需重启设备恢复） */
    s_remaining_attempts--;
    printf("Incorrect Password. %d Times Left\n", s_remaining_attempts);
    return 0;
}

/** @fn int func_unlock_get_remaining_attempts(void)
 *  @brief 获取剩余解锁尝试次数
 *  @return 剩余次数（0 表示已锁定）
 */
int func_unlock_get_remaining_attempts(void) {
    return s_remaining_attempts;
}

/** @fn int func_unlock_is_locked(void)
 *  @brief 检查解锁模块是否已锁定（尝试次数耗尽）
 *  @return 1 已锁定，0 未锁定
 */
int func_unlock_is_locked(void) {
    return s_remaining_attempts <= 0 ? 1 : 0;
}
