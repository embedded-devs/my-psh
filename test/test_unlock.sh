#!/bin/bash
# ============================================================
# 解锁功能端到端测试脚本
#
# 测试流程：
#   1. 启动 psh 程序（后台运行）
#   2. 发送 "debug" 命令，触发动态口令生成
#   3. 从 psh 输出中提取 Base64 动态口令
#   4. 用 unlock.sh 脚本解密动态口令，派生 8 字符短密钥
#   5. 将短密钥发送回 psh 完成解锁验证
#   6. 检查输出确认解锁是否成功
#
# 关键技术：使用命名管道（FIFO）实现与后台 psh 进程的双向通信
# ============================================================

# 创建临时目录，用于存放命名管道和输出文件
# mktemp -d 会在 /tmp 下创建一个唯一名称的临时目录
TMPDIR=$(mktemp -d)

# 注册退出清理钩子：脚本退出时（无论正常还是异常）自动删除临时目录
# trap 捕获 EXIT 信号，确保临时文件不会残留
trap 'rm -rf "$TMPDIR"' EXIT

# 创建命名管道（FIFO，First In First Out）
# 命名管道是一种特殊的文件类型，允许不相关的进程之间通信：
#   - 写入端：本脚本通过文件描述符 3 写入数据
#   - 读取端：psh 进程从该管道读取标准输入
# 与普通管道（|）不同，命名管道通过文件系统路径访问，可跨越独立进程
mkfifo "$TMPDIR/psh_in"

# 启动 psh 程序（后台运行），通过命名管道实现异步交互
#
# 命令解析：
#   timeout 20        - 设置 20 秒超时保护，防止 psh 挂死导致脚本永远等待
#   ./psh             - 运行被测程序
#   < "$TMPDIR/psh_in" - 将命名管道作为 psh 的标准输入
#                        psh 的 stdin 不再是终端，而是从这个 FIFO 读取
#                        当本脚本向 FIFO 写入时，psh 就能读到输入
#   > "$TMPDIR/psh_out" - 将 psh 的标准输出重定向到文件，供后续提取数据
#   2>&1              - 将标准错误也重定向到同一文件，确保所有输出都被捕获
#   &                  - 将整个命令放入后台执行（fork 子进程）
#                        本脚本继续往下执行，不会阻塞在 psh 上
#
# 整体数据流：
#   本脚本 --> FIFO 管道 --> psh stdin --> psh 处理 --> psh stdout/stderr --> 临时文件
timeout 20 ./psh < "$TMPDIR/psh_in" > "$TMPDIR/psh_out" 2>&1 &

# $! 是 Bash 特殊变量，保存最近一个后台进程的 PID
# 保存 PID 的目的：
#   1. 后续可用 wait $PSH_PID 等待 psh 进程结束
#   2. 如需要可用 kill $PSH_PID 强制终止 psh
PSH_PID=$!

# 以文件描述符 3 打开命名管道的写入端
# exec 3>"$TMPDIR/psh_in" 的作用：
#   - 将 FD 3 关联到命名管道的写入端
#   - 之后用 echo "xxx" >&3 即可向管道写入数据
#   - 保持管道持续打开，直到 exec 3>&- 显式关闭
# 为什么要用 FD 3 而不是直接 echo > "$TMPDIR/psh_in"：
#   - 每次直接重定向写入会反复打开/关闭管道
#   - 当所有写入端关闭时，读取端（psh）会收到 EOF 并认为输入结束
#   - 通过 FD 3 保持管道打开，可以多次写入而不会导致 psh 提前退出
exec 3>"$TMPDIR/psh_in"

# ====== 步骤 1：发送 "debug" 命令 ======
# 向 psh 发送 debug 命令，触发动态口令生成流程
# >&3 表示将输出重定向到文件描述符 3（即命名管道）
echo "debug" >&3

# 等待 psh 处理并输出动态口令
# psh 需要执行：生成随机数 R → 加载公钥 → RSA-OAEP 加密 R → 输出 Base64 动态口令
sleep 2

# ====== 步骤 2：从 psh 输出中提取 Base64 动态口令 ======
# grep 匹配仅包含 Base64 字符（A-Za-z0-9+/=）且长度 ≥20 的行
# 这是因为动态口令是 RSA-2048 加密后的 Base64 编码，长度约 344 字符
# 注意：管道输入时，psh 的 "# " 提示符可能与 Base64 输出在同一行
#       因此先用 sed 去除行首的 "# " 前缀，再匹配纯 Base64 行
# head -1 只取第一行匹配结果
CHALLENGE=$(sed 's/^# //' "$TMPDIR/psh_out" | grep -E '^[A-Za-z0-9+/=]{20,}$' | head -1)
echo "Challenge: $CHALLENGE"

# ====== 步骤 3：用 unlock.sh 解密动态口令，派生短密钥 ======
# unlock.sh 流程：Base64 解码 → RSA-OAEP 私钥解密得到 R → HMAC-SHA256 派生短密钥
# 2>&1 捕获 unlock.sh 的所有输出
# grep "短密钥:" 提取包含短密钥的行
# awk '{print $2}' 取第二列（短密钥值，如 "qEnCjcw="）
SHORT_KEY=$(./keys/unlock.sh "$CHALLENGE" 2>&1 | grep "短密钥:" | awk '{print $2}')
echo "Short key: $SHORT_KEY"

# ====== 步骤 4：将短密钥发送回 psh 作为解锁密码 ======
# psh 会将此输入与内部派生的短密钥做恒定时间比较
echo "$SHORT_KEY" >&3
sleep 1

# ====== 步骤 5：发送 "exit" 命令退出 psh ======
echo "exit" >&3
sleep 1

# 关闭文件描述符 3，释放命名管道的写入端
# exec 3>&- 关闭 FD 3：
#   - 管道写入端关闭后，psh 的 stdin 读到 EOF
#   - psh 检测到输入结束，正常退出
exec 3>&-

# 等待 psh 后台进程结束
# wait 会阻塞直到 $PSH_PID 对应的进程退出
# 2>/dev/null 抑制 "进程已退出" 之类的警告信息
wait $PSH_PID 2>/dev/null

# ====== 步骤 6：检查测试结果 ======
# 从 psh 的完整输出中过滤关键信息
# "Enter ASH Mode" - 解锁成功标志
# "Incorrect"      - 密码错误标志
echo "--- psh output ---"
cat "$TMPDIR/psh_out" | grep -E "BASH Mode|Incorrect|Password|Enter BASH"
