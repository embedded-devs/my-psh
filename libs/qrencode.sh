#!/bin/bash
# * =====================================================
# * Copyright © hk. 2022-2025. All rights reserved.
# * File name  : libqrencode.sh
# * Author     : 苏木
# * Date       : 2024-11-02
# * Description: 下载并编译安装 libqrencode v4.1.1
# * 
# * ======================================================
##
# 脚本和工程路径
# ========================================================
SCRIPT_NAME=${0#*/}
SCRIPT_CURRENT_PATH=${0%/*}
SCRIPT_ABSOLUTE_PATH=`cd $(dirname ${0}); pwd`
PROJECT_ROOT=${SCRIPT_ABSOLUTE_PATH}/..

# 颜色和日志标识
# ========================================================
step() {
    echo -e "\e[96m➤  $@\e[0m"
}

warning(){
    echo -n "⚠️  "
    echo -e "\e[33m$@\e[0m"
}

error() {
    echo -n "❌ "
    echo -e "\e[31m$@\e[0m"
}

success() {
    echo -n "✅ "
    echo -e "\e[32m$@\e[0m"
}

info() {
    echo -ne "\e[32mℹ️ [INFO]\e[0m"
    echo -e "\e[0m$@\e[0m"
}

# sudo 密码配置
SUDO_PASSWORD="000000"

# 带命令回显的执行函数
execute() {
    printf '\e[95m[CMD] %s\e[0m\n' "$*" >&2

    if [ "$1" = "sudo" ]; then
        shift
        if [ "$(id -u)" -eq 0 ]; then
            printf '\e[33m[SUDO] Already root, skip sudo\e[0m\n' >&2
            "$@"
        else
            printf '\e[33m[SUDO] Auto elevating privileges\e[0m\n' >&2
            echo "$SUDO_PASSWORD" | sudo -S "$@" 2>&1
        fi
    else
        "$@"
    fi
    local ret=$?
    if [ $ret -ne 0 ]; then
        printf '\e[31m❌ Command failed (exit code: %d): %s\e[0m\n' "$ret" "$*" >&2
        return $ret
    fi
    return 0
}

# 目录切换函数定义
cdi() {
    if command -v pushd &>/dev/null; then
        pushd $1 >/dev/null || return 1
    else
        cd $1
    fi
}

cdo() {
    if command -v popd &>/dev/null; then
        popd >/dev/null || return 1
    else
        cd -
    fi
}

# ========================================================
# 参数与模式
# ========================================================
EXECUTE_MODE=release
usage() {
    echo "================================================="
    echo -e "./${SCRIPT_NAME}          : 下载、编译并安装"
    echo -e "./${SCRIPT_NAME} -h       : 显示帮助信息"
    echo -e "./${SCRIPT_NAME} -d       : 调试模式(不自动删除已下载的压缩包和源码)"
    echo -e "./${SCRIPT_NAME} -q       : wget 不输出下载过程信息"
    echo -e "./${SCRIPT_NAME} download : 仅下载"
    echo -e "./${SCRIPT_NAME} build    : 下载、解压并编译"
    echo -e "./${SCRIPT_NAME} install  : 仅安装(需先编译)"
    echo -e "./${SCRIPT_NAME} clean    : 清理下载的压缩包和解压的源码"
    echo -e "ARCH=arm ./${SCRIPT_NAME}  : 交叉编译 (arm-linux-gnueabihf-gcc)"
    echo "================================================="
}

step "There are $# parameters: $@ (\$1~\$$#)"

while getopts "dqh" arg
    do
        case ${arg} in
            d) EXECUTE_MODE="debug" ;;
            q) Q="-q" ;;
            h) usage; exit 0 ;;
            ?)
                error "unknown argument..."
                exit 1
                ;;
        esac
    done

shift $((OPTIND - 1))
ACTION=${1:-all}

# ========================================================
# 交叉编译配置
# ========================================================
# ARCH=arm 时使用交叉编译工具链，否则使用本地编译
if [ -n "${ARCH}" ]; then
    case "${ARCH}" in
        arm)
            CROSS_PREFIX=arm-linux-gnueabihf-
            ;;
        *)
            error "Unsupported ARCH=${ARCH}, only 'arm' is supported"
            exit 1
            ;;
    esac
else
    CROSS_PREFIX=
fi

# ========================================================
# 功能实现
# ========================================================
ZIP_NAME=v4.1.1.zip
SRC_DIR_NAME=libqrencode-4.1.1
ZIP_FILE=${SCRIPT_ABSOLUTE_PATH}/${ZIP_NAME}
SRC_DIR=${SCRIPT_ABSOLUTE_PATH}/${SRC_DIR_NAME}
BUILD_DIR=${SRC_DIR}/_build
INSTALL_PREFIX=${SRC_DIR}/_install
DOWNLOAD_LINK=https://github.com/fukuchi/libqrencode/archive/refs/tags/v4.1.1.zip

# 检查并安装依赖
check_dependencies() {
    step "checking dependencies..."

    # 依赖列表: "命令名" 格式，命令名与包名相同
    local deps=("wget" "unzip" "cmake")
    local need_update=false

    # 本地编译时额外检查 gcc 和 make
    if [ -z "${CROSS_PREFIX}" ]; then
        deps+=("gcc" "make")
    fi

    for dep in "${deps[@]}"; do
        if ! command -v ${dep} &>/dev/null; then
            warning "${dep} not found, installing ${dep}..."
            if [ "${need_update}" = false ]; then
                execute sudo apt-get update
                need_update=true
            fi
            execute sudo apt-get install -y ${dep}
        fi
    done

    # 交叉编译模式：检查交叉编译工具链
    if [ -n "${CROSS_PREFIX}" ]; then
        if ! command -v ${CROSS_PREFIX}gcc &>/dev/null; then
            error "cross-compiler ${CROSS_PREFIX}gcc not found, please install it first"
            exit 1
        fi
    fi
}

# 下载并解压源码包
# 优先级：源码目录已存在 → 压缩包已存在直接解压 → 下载后解压
do_download_src() {
   step "preparing ${SRC_DIR_NAME} source..."

   # 1. 源码目录已存在，无需下载和解压
   if [ -d "${SRC_DIR}" ]; then
      info "source directory already exists, skip download and unpack."
      success "source ready..."
      return 0
   fi

   # 2. 压缩包已存在，直接解压
   if [ -f "${ZIP_FILE}" ]; then
      info "zip file already exists, unpacking..."
   else
      # 3. 压缩包不存在，下载
      info "downloading ${ZIP_NAME}..."
      execute wget ${Q} -c ${DOWNLOAD_LINK} -O ${ZIP_FILE}
   fi

   # 解压
   execute unzip -q ${ZIP_FILE} -d ${SCRIPT_ABSOLUTE_PATH}
   success "download and unpack done..."
}

# 解压源码包到当前目录（已由 do_download_src 合并处理，保留接口兼容）
do_unzip_package() {
    step "start unpacking the ${SRC_DIR_NAME} package ..."

    if [ ! -d "${SRC_DIR}" ];then
        execute unzip -q ${ZIP_FILE} -d ${SCRIPT_ABSOLUTE_PATH}
    else
        info "source directory already exists, skip unzip."
    fi
    success "unpack done..."
}

# 编译
do_build() {
    step "start building ${SRC_DIR_NAME} ..."

    if [ ! -d "${SRC_DIR}" ]; then
        error "source directory not found: ${SRC_DIR}"
        return 1
    fi

    cdi ${SRC_DIR}

    if [ -d "${BUILD_DIR}" ]; then
        execute rm -rf ${BUILD_DIR}
    fi

    execute mkdir -p ${BUILD_DIR}
    cdi ${BUILD_DIR}

    if [ -n "${CROSS_PREFIX}" ]; then
        info "cross-compiling for ARCH=${ARCH}, using ${CROSS_PREFIX}gcc"
        execute cmake ${SRC_DIR} \
            -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
            -DWITH_TOOLS=NO \
            -DBUILD_SHARED_LIBS=NO \
            -DCMAKE_C_COMPILER=${CROSS_PREFIX}gcc \
            -DCMAKE_SYSTEM_NAME=Linux \
            -DCMAKE_SYSTEM_PROCESSOR=arm
    else
        execute cmake ${SRC_DIR} \
            -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} \
            -DWITH_TOOLS=NO \
            -DBUILD_SHARED_LIBS=NO
    fi
    execute make -j$(nproc)

    cdo
    success "build done..."
}

# 安装
do_install() {
    step "start installing ${SRC_DIR_NAME} to ${INSTALL_PREFIX} ..."

    if [ ! -d "${BUILD_DIR}" ]; then
        error "build directory not found: ${BUILD_DIR}"
        return 1
    fi

    cdi ${BUILD_DIR}
    execute make install
    cdo
    success "install done..."
}

# 删除构建产物
do_clean() {
   cdi ${SRC_DIR}
   if [ -d "_build" ]; then
      execute rm -rf _build
   fi
   if [ -d "_install" ]; then
      execute rm -rf _install
   fi
   cdo
   success "clean done..."
}

# 打印菜单
do_echo_menu() {
	echo "================================================="
	echo -e "               libqrencode installer "
	echo "================================================="
	echo -e "current path        :$(pwd)"
    echo -e "SCRIPT_CURRENT_PATH :${SCRIPT_CURRENT_PATH}"
    echo -e "SCRIPT_ABSOLUTE_PATH:${SCRIPT_ABSOLUTE_PATH}"
    echo -e "INSTALL_PREFIX      :${INSTALL_PREFIX}"
    echo -e "CROSS_PREFIX        :${CROSS_PREFIX:-local}"
    echo -e "SHELL_PARAM         :($# total) arg=$*"
	echo ""
	echo "================================================="
}

do_echo_menu
check_dependencies
case "${ACTION}" in
    all)
        do_download_src
        do_build
        do_install
        ;;
    download)
        do_download_src
        ;;
    build)
        do_build
        ;;
    install)
        do_install
        ;;
    clean)
        do_clean
        ;;
    *)
        error "unknown action: ${ACTION}"
        usage
        exit 1
        ;;
esac

exit $?
