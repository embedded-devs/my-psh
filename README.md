## 一、 概述

### 1. Shell 家族简介

在 Linux 生态中，常见的 Shell 实现各有定位：

- **sh**（Bourne Shell）：Unix 最早的 Shell，POSIX 标准的基础原型，功能精简
- **bash**（Bourne Again Shell）：GNU 项目标准 Shell，Linux 发行版默认，功能丰富（命令补全、历史记录、脚本扩展等）
- **ash**（Almquist Shell）：BusyBox 内置轻量 Shell，体积小，广泛用于嵌入式设备
- **psh**（Protect Shell）：本项目实现的安全门禁层，本身并非完整 Shell，而是对 bash / ash / sh 的访问控制前置——登录时接管终端，通过挑战-应答认证后释放目标 Shell（默认 `/bin/sh`，可通过参数指定 `/bin/bash` 等）
- ...

### 2. psh 简介

psh（Protect Shell）是一款面向嵌入式 Linux 设备的安全门禁 Shell。设备每次开机进入受限 Shell 环境，仅支持 `help`、`debug`、`exit` 三条指令。通过 RSA-2048 挑战-应答机制实现安全解锁，解锁后释放真正的登录 Shell。

设备端仅持有 RSA 公钥，私钥由管理员离线保管。物理窃取设备无法自行解锁，从根本上杜绝未授权访问。

## 二、 安全架构

### 1. 挑战-应答流程

设备开机后由 PSA Crypto API 生成 32 字节密码学安全随机数 `R`（重启前保持不变），每次执行 `debug` 命令时触发以下流程：

- **设备端**：`R` → RSA-OAEP(SHA-256) 公钥加密 → 256 字节密文 → 拼接 1 字节版本前缀 `0x00` → Base64 编码 → 约 344 字符动态口令
- **管理端**：Base64 解码 → 跳过首字节 → RSA-OAEP 私钥解密 → 恢复 `R` → HMAC-SHA256(R, "SHELL-UNLOCK") → 取前 6 字节 → Base64 → 8 字符短密钥
- **设备端**：用户输入短密钥 → 恒定时间比较 → 一致则擦除 `R` 并 `execvp` 进入正常 Shell，不一致则递减尝试次数（5 次耗尽后锁定）

### 2. 短密钥派生算法

```c
SHORT_KEY = Base64( HMAC-SHA256(R, "SHELL-UNLOCK")[0..5] )
```

- 输入：32 字节随机数 `R` 作为 HMAC 密钥
- 消息：固定字符串 `"SHELL-UNLOCK"`
- 输出：取 HMAC 前 6 字节 → Base64 编码 → 8 字符短密钥（6%3 = 0，无 `=` 填充）
- 密钥空间：2^48 ≈ 2.8 万亿，配合 5 次尝试限制，暴力破解不可行

## 三、 快速开始

### 1. 环境依赖

- GCC（本地编译）或 `arm-linux-gnueabihf-gcc`（ARM 交叉编译）
- mbedTLS v4.0.0（PSA Crypto API，`build.sh` 自动下载编译）
- libqrencode v4.1.1（可选，QR 码显示，默认关闭）
- OpenSSL（管理端，用于密钥生成及解锁脚本）

### 2. 生成密钥对

```bash
cd keys
./gen_keys.sh         # 生成 RSA-2048 密钥对（默认）
./gen_keys.sh 4096    # 生成 RSA-4096 密钥对（生产环境推荐）
```

生成文件：

- `keys/public_key.pem`：公钥，部署到设备端，无密码保护
- `keys/private_key.pem`：私钥，管理员离线保管，AES-256 加密（密码 `000000`）

### 3. 编译构建

```bash
./build.sh              # 完整构建（下载编译依赖库 + 编译 psh）
./build.sh libs         # 仅构建依赖库
./build.sh build        # 仅编译 psh
./build.sh clean        # 清理构建产物
./build.sh -l mbedtls   # 仅编译指定依赖库
ARCH=arm ./build.sh     # 交叉编译（ARM 目标平台）
```

编译产物为项目根目录下的 `psh` 可执行文件。交叉编译时使用 `-static` 静态链接，避免目标平台 glibc 版本不匹配。

Git 版本信息自动嵌入编译产物，格式为 `SM-YYYYMMDD-<hash>-n<count>[-dirty]`，启动时在横幅中显示。

### 4. 运行

```bash
./psh                                    # 交互模式（默认解锁后启动 /bin/sh）
./psh /bin/bash                          # 指定解锁后的 Shell 路径
UNLOCK_PUBKEY_PATH=/secure/rsa_pub.pem ./psh   # 通过环境变量覆盖公钥路径
```

## 四、 使用指南

### 1. 受限命令

psh 启动后打印版本横幅，进入受限 Shell 循环（提示符 `#`），仅支持以下命令：

- `help`：显示支持的命令列表
- `debug`：生成 RSA 动态口令并提示输入短密钥解锁
- `exit` / `quit`：退出 psh
- `Ctrl+D`（EOF）：退出 psh

输入任何其他命令均提示 `'<cmd>' Not Supported, Try 'help'`。

### 2. 解锁操作

**步骤 1**——设备端输入 `debug`，屏幕输出约 344 字符的 Base64 动态口令（末尾 1 个 `=`）及可选 QR 码，随后显示 `Password:` 等待输入：

```shell
# debug
m9X2vF8Kd3s...(约 344 字符，末尾 1 个 =)...=
Password:
```

**步骤 2**——管理端运行解锁脚本：

```bash
cd keys
./unlock.sh "m9X2vF8Kd3s..."
```

脚本输出 8 字符短密钥（如 `aGJjZGVm`）。另有 Windows PowerShell 版本 `keys/unlock.ps1`。

**步骤 3**——在设备端 `Password:` 提示后输入短密钥（输入不回显）：

- 验证通过：显示 `Enter BASH Mode.` 及时间戳，进入正常 Shell，同时设置环境变量 `PSH_AUTH=1`
- 验证失败：显示 `Incorrect Password. X Times Left`，返回 `#` 提示符
- 5 次失败后锁定：后续 `debug` 命令静默无响应，需重启设备恢复

### 3. 管理端脚本工作原理

`keys/unlock.sh` 接收 Base64 动态口令作为参数，自动完成：

（1）Base64 解码动态口令

（2）跳过 1 字节版本前缀（`0x00`）

（3）RSA-OAEP(SHA-256) 私钥解密 → 恢复 `R`（32 字节）

（4）HMAC-SHA256(R, "SHELL-UNLOCK") → 取前 6 字节

（5）Base64 编码 → 8 字符短密钥

私钥文件默认为脚本同目录下的 `private_key.pem`，密码为 `000000`。HMAC 计算优先使用 OpenSSL HMAC 模式，fallback 至 Python3。

## 五、 技术参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| RSA 密钥长度 | 2048 位 | 生产环境建议 4096，修改 `func_unlock.h` 中 `UNLOCK_RSA_KEY_BITS` |
| 加密算法 | RSA-OAEP / SHA-256 / MGF1 | 基于 mbedTLS PSA Crypto API |
| 随机数 R 长度 | 32 字节 | 密码学安全伪随机数 |
| 密文长度 | 256 字节 | RSA-2048 即 `key_bits / 8` |
| 版本前缀 | 1 字节（`0x00`） | 预留协议扩展，使 257 字节 → Base64 末尾仅 1 个 `=` |
| 动态口令长度 | 约 344 字符 | Base64 编码，末尾 1 个 `=` |
| 短密钥原始字节 | 6 字节 | HMAC-SHA256 输出取前 6 字节 |
| 短密钥显示长度 | 8 字符 | Base64 编码，6%3 = 0 无 `=` 填充 |
| 最大尝试次数 | 5 次 | 超限锁定，需重启设备恢复 |
| 内存安全 | 恒定时间比较 + volatile 擦除 | 防止时序攻击和冷启动攻击 |
| 密码学库 | mbedTLS v4.0.0 | 体积小，适合嵌入式 |
| QR 码库 | libqrencode v4.1.1 | 可选，通过 `PSH_QRCODE_ENA` 宏控制 |

## 六、 安全特性

- **无密钥泄露风险**：设备端仅存储 RSA 公钥，私钥由管理员离线保管，物理窃取设备无法推导私钥或生成正确短密钥
- **一次一密**：RSA-OAEP 随机填充确保同一 `R` 每次加密产生不同密文，回放攻击无效
- **大密钥空间**：短密钥空间 2^48 ≈ 2.8 万亿，配合 5 次在线尝试限制，暴力破解不可行
- **恒定时间比较**：使用 XOR 累积差异的恒定时间算法比较短密钥，防止通过响应耗时推断密钥内容的时序攻击
- **安全内存擦除**：`R` 及中间敏感值使用 `volatile` 指针强制清零，防止编译器优化删除及冷启动攻击提取残留数据
- **私钥加密存储**：管理端私钥使用 AES-256 加密，使用时需输入密码
- **锁定保护**：5 次失败后 `debug` 命令静默无响应，不泄露任何状态信息，需重启设备恢复
- **无回显密码输入**：使用 termios 关闭终端 `ECHO` 标志
- **进程替换**：解锁后通过 `execvp` 替换进程镜像，不留 psh 进程残留

## 七、 项目结构

```text
psh/
├── main.c                  # 程序入口
├── Makefile                # 编译构建
├── build.sh                # 统一构建脚本（依赖库下载 + 编译）
├── build-docker.ps1        # Docker 构建脚本（Windows PowerShell）
├── src/
│   ├── func_psh.c/.h       # PSH 受限 Shell 主循环
│   ├── func_unlock.c/.h    # RSA 挑战-应答解锁核心模块
│   ├── func_rsa.c/.h       # PSA Crypto RSA 操作封装
│   ├── func_base64.c/.h    # 自定义 Base64 编解码
│   └── func_qrencode.c/.h  # QR 码生成输出
├── keys/
│   ├── gen_keys.sh         # RSA 密钥对生成脚本
│   ├── unlock.sh           # 管理端解锁脚本（bash）
│   ├── unlock.ps1          # 管理端解锁脚本（PowerShell）
│   ├── public_key.pem      # 公钥（部署到设备）
│   └── private_key.pem     # 私钥（离线保管）
├── libs/
│   ├── mbedtls.sh          # mbedTLS v4.0.0 下载编译安装脚本
│   └── qrencode.sh         # libqrencode v4.1.1 下载编译安装脚本
├── test/
│   └── test_unlock.sh      # 端到端自动测试脚本
├── docs/
│   └── base64_padding_principle.md  # Base64 填充原理说明
└── examples/
    └── psh.c               # 早期原型版本
```

## 八、 部署说明

### 1. 嵌入 Linux 设备

- **BusyBox init**：在 `/etc/inittab` 中添加 `::respawn:-/bin/psh`
- **systemd**：创建 `psh.service`，设置 `Restart=always` 和 `StandardInput=tty`
- 将 `psh` 可执行文件及 `keys/public_key.pem` 部署至设备对应路径
- 可通过环境变量 `UNLOCK_PUBKEY_PATH` 覆盖公钥路径，无需重新编译

### 2. RSA 密钥位数升级

若需使用 RSA-4096，修改 `src/func_unlock.h` 后重新编译：

```c
#define UNLOCK_RSA_KEY_BITS  4096
```

同时重新生成密钥对：`cd keys && ./gen_keys.sh 4096`

### 3. 启用 QR 码

修改 `src/func_psh.h`：

```c
#define PSH_QRCODE_ENA  1
```

重新编译后，`debug` 命令将同时显示 QR 码（UTF-8 块字符）和 Base64 文本。

---

*本文档由 markdowncli 技能辅助生成*
