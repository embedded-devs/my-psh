#!/bin/bash
# =====================================================
# 挑战码解密脚本
# 用法: ./unlock.sh <Base64动态口令>
#
# 流程:
#   1. Base64 解码动态口令 → RSA-OAEP 密文
#   2. 私钥解密 → R (32 字节)
#   3. HMAC-SHA256(R, "SHELL-UNLOCK") 取前5字节 → Base64 → 8字符短密钥
# =====================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_FILE="${SCRIPT_DIR}/private_key.pem"
KEY_PASS="000000"

# 检查参数
if [ -z "$1" ]; then
    echo "用法: $0 <Base64动态口令>"
    echo ""
    echo "示例:"
    echo "  $0 'a3f8B...Base64Challenge...=='"
    echo ""
    echo "说明:"
    echo "  将 Base64 动态口令解密，派生 8 字符短密钥"
    echo "  私钥文件: ${KEY_FILE}"
    echo "  私钥密码: ${KEY_PASS}"
    exit 1
fi

CHALLENGE="$1"

# 检查私钥文件
if [ ! -f "$KEY_FILE" ]; then
    echo "错误: 找不到私钥文件 ${KEY_FILE}"
    echo "请先运行 gen_keys.sh 生成密钥对"
    exit 1
fi

# 创建临时目录
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

echo "============================================"
echo "  挑战码解密"
echo "============================================"
echo ""

# ===== Step 1: Base64 解码 + 跳过版本前缀 + RSA-OAEP 解密 → R =====
echo "[1/3] RSA-OAEP 解密中..."
printf '%s' "$CHALLENGE" | base64 -d 2>/dev/null | \
    tail -c +2 | \
    openssl pkeyutl -decrypt \
        -inkey "$KEY_FILE" \
        -passin "pass:${KEY_PASS}" \
        -pkeyopt rsa_padding_mode:oaep \
        -pkeyopt rsa_oaep_md:sha256 \
    > "$TMPDIR/R.bin" 2>/dev/null

if [ $? -ne 0 ] || [ ! -s "$TMPDIR/R.bin" ]; then
    echo "错误: RSA 解密失败"
    echo "  - 请确认动态口令完整无误"
    echo "  - 请确认私钥文件与设备端公钥匹配"
    exit 1
fi

R_SIZE=$(wc -c < "$TMPDIR/R.bin")
R_HEX=$(xxd -p -c 64 "$TMPDIR/R.bin")
echo "  R (${R_SIZE} bytes): ${R_HEX}"

# ===== Step 2: HMAC-SHA256(R, "SHELL-UNLOCK") =====
echo "[2/3] 派生短密钥 (HMAC-SHA256)..."

# 方法1: OpenSSL HMAC (需 OpenSSL 1.1+)
if printf '%s' "SHELL-UNLOCK" | \
    openssl dgst -sha256 -mac HMAC -macopt "hexkey:${R_HEX}" -binary \
    > "$TMPDIR/hmac.bin" 2>/dev/null; then

    # Step 3: 取前6字节 → Base64（6%3=0，无 '=' 填充）
    SHORT_KEY=$(head -c 6 "$TMPDIR/hmac.bin" | base64 | tr -d '\n')

# 方法2: Python3 fallback
elif command -v python3 &>/dev/null; then
    echo "  (使用 python3 计算 HMAC)"
    SHORT_KEY=$(python3 -c "
import hmac, hashlib, base64, sys
r = open('${TMPDIR}/R.bin', 'rb').read()
h = hmac.new(r, b'SHELL-UNLOCK', hashlib.sha256).digest()
print(base64.b64encode(h[:6]).decode(), end='')
")
    if [ $? -ne 0 ]; then
        echo "错误: HMAC 计算失败"
        exit 1
    fi
else
    echo "错误: HMAC 计算失败"
    echo "  需要 OpenSSL 1.1+ 或 Python3"
    exit 1
fi

echo ""
echo "============================================"
echo "  解密结果"
echo "============================================"
echo ""
echo "  短密钥: ${SHORT_KEY}"
echo ""
echo "请在设备端输入此短密钥完成解锁"
