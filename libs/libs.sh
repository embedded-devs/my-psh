#!/bin/bash
# * =====================================================
# * Copyright © hk. 2022-2025. All rights reserved.
# * File name  : libs.sh
# * Author     : 苏木
# * Date       : 2024-11-02
# * Description: 批量下载、编译并安装依赖库
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
EXECUTE_MODE=release
usage() {
    echo "================================================="
    echo -e "./${SCRIPT_NAME}          : 下载、编译并安装所有库"
    echo -e "./${SCRIPT_NAME} -h       : 显示帮助信息"
    echo -e "./${SCRIPT_NAME} -l libs  : 仅构建指定库(逗号分隔, 可选: mbedtls,qrencode)"
    echo -e "./${SCRIPT_NAME} download : 仅下载"
    echo -e "./${SCRIPT_NAME} build    : 编译"
    echo -e "./${SCRIPT_NAME} install  : 安装"
    echo -e "./${SCRIPT_NAME} clean    : 清理构建产物"
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
# 功能实现
# ========================================================

# 构建单个库
do_build_lib() {
    local lib=$1
    local script="${SCRIPT_ABSOLUTE_PATH}/${lib}.sh"

    if [ ! -f "${script}" ]; then
        error "script not found: ${script}"
        return 1
    fi

    step "[${lib}] start ${ACTION}..."

    if [ "${ACTION}" = "all" ]; then
        execute bash "${script}" download
        execute bash "${script}" build
        execute bash "${script}" install
    else
        execute bash "${script}" "${ACTION}"
    fi

    success "[${lib}] ${ACTION} done..."
}

# 打印菜单
do_echo_menu() {
    echo "================================================="
    echo -e "               libs batch installer "
    echo "================================================="
    echo -e "current path        :$(pwd)"
    echo -e "SCRIPT_CURRENT_PATH :${SCRIPT_CURRENT_PATH}"
    echo -e "SCRIPT_ABSOLUTE_PATH:${SCRIPT_ABSOLUTE_PATH}"
    echo -e "TARGET_LIBS         :${TARGET_LIBS}"
    echo -e "ACTION              :${ACTION}"
    echo -e "SHELL_PARAM         :($# total) arg=$*"
    echo ""
    echo "================================================="
}

do_echo_menu

case "${ACTION}" in
    all|download|build|install|clean)
        FAILED=()
        for lib in ${TARGET_LIBS}; do
            if ! do_build_lib "${lib}"; then
                FAILED+=("${lib}")
            fi
        done

        echo ""
        echo "================================================="
        if [ ${#FAILED[@]} -eq 0 ]; then
            success "all done: ${TARGET_LIBS}"
        else
            error "failed: ${FAILED[*]}"
            exit 1
        fi
        ;;
    *)
        error "unknown action: ${ACTION}"
        usage
        exit 1
        ;;
esac

exit $?
