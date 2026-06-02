#ifndef FUNC_RSA_H
#define FUNC_RSA_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief 初始化 PSA Crypto 库（使用 RSA 功能前必须调用）
 * @return 0 成功，-1 失败
 */
int func_rsa_init(void);

/**
 * @brief 释放 PSA Crypto 库资源
 */
void func_rsa_free(void);

/**
 * @brief 生成 RSA 密钥对
 * @param key_bits 密钥位数（推荐 2048 或 4096）
 * @param key_id   输出参数，生成的密钥 ID
 * @return 0 成功，-1 失败
 */
int func_rsa_generate_key(uint32_t key_bits, uint32_t *key_id);

/**
 * @brief 使用公钥加密数据（RSA PKCS#1 v1.5）
 * @param key_id        RSA 密钥对 ID
 * @param plaintext     明文数据
 * @param plaintext_len 明文长度
 * @param ciphertext    输出密文缓冲区
 * @param cipher_size   密文缓冲区大小
 * @param cipher_len    输出参数，实际密文长度
 * @return 0 成功，-1 失败
 */
int func_rsa_encrypt(uint32_t key_id,
                     const uint8_t *plaintext, size_t plaintext_len,
                     uint8_t *ciphertext, size_t cipher_size,
                     size_t *cipher_len);

/**
 * @brief 使用私钥解密数据（RSA PKCS#1 v1.5）
 * @param key_id        RSA 密钥对 ID
 * @param ciphertext    密文数据
 * @param cipher_len    密文长度
 * @param plaintext     输出明文缓冲区
 * @param plain_size    明文缓冲区大小
 * @param plain_len     输出参数，实际明文长度
 * @return 0 成功，-1 失败
 */
int func_rsa_decrypt(uint32_t key_id,
                     const uint8_t *ciphertext, size_t cipher_len,
                     uint8_t *plaintext, size_t plain_size,
                     size_t *plain_len);

/**
 * @brief 销毁 RSA 密钥，释放资源
 * @param key_id 密钥 ID
 */
void func_rsa_destroy_key(uint32_t key_id);

/**
 * @brief RSA 公钥加密/私钥解密 自测函数
 */
void func_rsa_test(void);

#endif
