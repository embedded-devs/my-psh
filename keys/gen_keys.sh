#!/bin/bash
# =====================================================
# RSA 密钥对生成脚本
# 用法: ./gen_keys.sh [密钥位数]
# 生成文件:
#   - keys/private_key.pem  (AES-256 加密，密码: 000000)
#   - keys/public_key.pem   (公钥，无密码保护)
# =====================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="${SCRIPT_DIR}"
KEY_PASS="000000"
KEY_BITS="${1:-2048}"

echo "============================================"
echo "  RSA 密钥对生成"
echo "============================================"
echo "密钥位数: ${KEY_BITS}"
echo "私钥密码: ${KEY_PASS}"
echo "输出目录: ${KEYS_DIR}"
echo ""

# 检查 openssl
if ! command -v openssl &>/dev/null; then
    echo "错误: 未找到 openssl 命令"
    exit 1
fi

# 创建目录
mkdir -p "${KEYS_DIR}"

# ===== 生成 RSA 私钥（AES-256 加密） =====
echo "[1/2] 生成 RSA-${KEY_BITS} 私钥..."
openssl genrsa -aes256 -passout "pass:${KEY_PASS}" \
    -out "${KEYS_DIR}/private_key.pem" ${KEY_BITS}
if [ $? -ne 0 ]; then
    echo "错误: 私钥生成失败"
    exit 1
fi
chmod 600 "${KEYS_DIR}/private_key.pem"
echo "  -> ${KEYS_DIR}/private_key.pem"

# ===== 导出公钥 =====
echo "[2/2] 导出公钥..."
openssl rsa -in "${KEYS_DIR}/private_key.pem" \
    -passin "pass:${KEY_PASS}" \
    -pubout -out "${KEYS_DIR}/public_key.pem"
if [ $? -ne 0 ]; then
    echo "错误: 公钥导出失败"
    rm -f "${KEYS_DIR}/private_key.pem"
    exit 1
fi
echo "  -> ${KEYS_DIR}/public_key.pem"

echo ""
echo "============================================"
echo "  生成完成"
echo "============================================"
echo ""
echo "  公钥 (部署到设备端): keys/public_key.pem"
echo "  私钥 (管理员保管):   keys/private_key.pem"
echo ""
echo "公钥信息:"
openssl rsa -pubin -in "${KEYS_DIR}/public_key.pem" -noout -text 2>/dev/null | head -3
echo ""
echo "公钥指纹:"
openssl rsa -pubin -in "${KEYS_DIR}/public_key.pem" -noout -fingerprint 2>/dev/null
