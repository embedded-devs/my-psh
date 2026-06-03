#!/bin/bash
# * =====================================================
# * Copyright © hk. 2022-2025. All rights reserved.
# * File name  : build.sh
# * Author     : 苏木
# * Date       : 2024-11-02
# * Description: 统一构建脚本 — 依赖库下载编译 + psh 编译
# *
# * 用法:
# *   ./build.sh              构建依赖库并编译 psh
# *   ./build.sh libs         仅构建依赖库(下载、编译、安装)
# *   ./build.sh build        仅编译 psh (调用 Makefile)
# *   ./build.sh clean        清理 psh 构建产物
# *   ./build.sh -l mbedtls   仅构建指定库(逗号分隔, 如 -l mbedtls,qrencode)
# *   ARCH=arm ./build.sh     交叉编译 (arm-linux-gnueabihf-gcc)
# *   ARCH=arm ./build.sh libs   交叉编译仅构建依赖库
# *   ARCH=arm ./build.sh build  交叉编译仅编译 psh
# * ======================================================
##
# 脚本和工程路径
# ========================================================
SCRIPT_NAME=${0#*/}
SCRIPT_CURRENT_PATH=${0%/*}
SCRIPT_ABSOLUTE_PATH=`cd $(dirname ${0}); pwd`
PROJECT_ROOT=${SCRIPT_ABSOLUTE_PATH}

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

# 带命令回显的执行函数
execute() {
    printf '\e[95m[CMD] %s\e[0m\n' "$*" >&2
    "$@"
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
usage() {
    echo "================================================="
    echo -e "./${SCRIPT_NAME}          : 构建依赖库并编译 psh"
    echo -e "./${SCRIPT_NAME} -h       : 显示帮助信息"
    echo -e "./${SCRIPT_NAME} -l libs  : 仅构建指定库(逗号分隔, 可选: mbedtls,qrencode)"
    echo -e "./${SCRIPT_NAME} libs     : 仅构建依赖库"
    echo -e "./${SCRIPT_NAME} build    : 仅编译 psh (调用 Makefile)"
    echo -e "./${SCRIPT_NAME} clean    : 清理 psh 构建产物"
    echo -e "ARCH=arm ./${SCRIPT_NAME}  : 交叉编译 (arm-linux-gnueabihf-gcc)"
    echo "================================================="
}

LIBS=("mbedtls" "qrencode")

step "There are $# parameters: $@ (\$1~\$$#)"

while getopts "l:h" arg
    do
        case ${arg} in
            l)
                TARGET_LIBS=()
                IFS=',' read -ra INPUT_LIBS <<< "$OPTARG"
                for lib in "${INPUT_LIBS[@]}"; do
                    if [[ " ${LIBS[*]} " =~ " ${lib} " ]]; then
                        TARGET_LIBS+=("$lib")
                    else
                        error "unknown lib: ${lib}, available: ${LIBS[*]}"
                        exit 1
                    fi
                done
                ;;
            h) usage; exit 0 ;;
            ?)
                error "unknown argument..."
                exit 1
                ;;
        esac
    done

shift $((OPTIND - 1))
ACTION=${1:-all}
TARGET_LIBS=${TARGET_LIBS:-${LIBS[@]}}

# ========================================================
# 交叉编译配置
# ========================================================
if [ -n "${ARCH}" ]; then
    case "${ARCH}" in
        arm)
            CROSS_PREFIX=arm-linux-gnueabihf-
            MAKE_ARCH="ARCH=arm"
            ;;
        *)
            error "Unsupported ARCH=${ARCH}, only 'arm' is supported"
            exit 1
            ;;
    esac
else
    CROSS_PREFIX=
    MAKE_ARCH=
fi

# ========================================================
# 功能实现
# ========================================================
LIBS_DIR=${PROJECT_ROOT}/libs

# 构建单个库
do_build_lib() {
    local lib=$1
    local script="${LIBS_DIR}/${lib}.sh"

    if [ ! -f "${script}" ]; then
        error "script not found: ${script}"
        return 1
    fi

    step "[${lib}] start building..."

    # 传递 ARCH 环境变量给子脚本
    execute env ARCH="${ARCH}" bash "${script}"

    success "[${lib}] done..."
}

# 构建所有依赖库
do_libs() {
    step "building dependency libraries..."

    FAILED=()
    for lib in ${TARGET_LIBS}; do
        if ! do_build_lib "${lib}"; then
            FAILED+=("${lib}")
        fi
    done

    echo ""
    echo "================================================="
    if [ ${#FAILED[@]} -eq 0 ]; then
        success "all libs done: ${TARGET_LIBS}"
    else
        error "failed libs: ${FAILED[*]}"
        return 1
    fi
}

# 编译 psh（调用 Makefile）
do_build_psh() {
    step "building psh (make ${MAKE_ARCH})..."

    cdi ${PROJECT_ROOT}
    execute make ${MAKE_ARCH}
    cdo

    if [ -f "${PROJECT_ROOT}/psh" ]; then
        success "psh binary ready: ${PROJECT_ROOT}/psh"
    else
        error "psh binary not found after build"
        return 1
    fi
}

# 清理 psh 构建产物
do_clean_psh() {
    step "cleaning psh build artifacts..."

    cdi ${PROJECT_ROOT}
    execute make ${MAKE_ARCH} clean
    cdo

    success "psh clean done..."
}

# 打印菜单
do_echo_menu() {
    echo "================================================="
    echo -e "               psh build script "
    echo "================================================="
    echo -e "current path        :$(pwd)"
    echo -e "PROJECT_ROOT        :${PROJECT_ROOT}"
    echo -e "TARGET_LIBS         :${TARGET_LIBS}"
    echo -e "ACTION              :${ACTION}"
    echo -e "CROSS_PREFIX        :${CROSS_PREFIX:-local}"
    echo -e "SHELL_PARAM         :($# total) arg=$*"
    echo ""
    echo "================================================="
}

do_echo_menu

case "${ACTION}" in
    all)
        do_libs
        do_build_psh
        ;;
    libs)
        do_libs
        ;;
    build)
        do_build_psh
        ;;
    clean)
        do_clean_psh
        ;;
    *)
        error "unknown action: ${ACTION}"
        usage
        exit 1
        ;;
esac

exit $?
