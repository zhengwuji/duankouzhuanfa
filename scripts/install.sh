#!/usr/bin/env bash
#
# PortTransit 一键安装 / 卸载 / 重置密码脚本
#
# 支持：Debian 11/12/13、Ubuntu 20.04/22.04/24.04 及更新的版本
# 架构：amd64、arm64
#
# 用法：
#   bash install.sh                          交互式安装中转服务端
#   bash install.sh --transport vless        指定协议安装
#   bash install.sh --port 443               指定监听端口
#   bash install.sh --uninstall              彻底卸载
#   bash install.sh --reset-password         重置管理后台密码
#   bash install.sh --status                 查看运行状态
#
# 该脚本只做四件事：安装依赖、放置二进制、生成配置、注册系统服务。
# 所有配置逻辑都在 porttransit 二进制内部，脚本不复制它的判断。

set -Eeuo pipefail

# 出错时打印行号与命令，否则远程排障只能靠猜。
trap 'echo "!! 第 $LINENO 行执行失败：$BASH_COMMAND" >&2' ERR

readonly BIN_NAME="porttransit"
readonly BIN_PATH="/usr/local/bin/${BIN_NAME}"
readonly CONFIG_DIR="/etc/porttransit"
readonly CONFIG_PATH="${CONFIG_DIR}/config.json"
readonly DATA_DIR="/var/lib/porttransit"
readonly LOG_DIR="/var/log/porttransit"
readonly UNIT_PATH="/etc/systemd/system/${BIN_NAME}.service"
# 独立文件而不是往 /etc/sysctl.conf 里追加：卸载时能干净删除，也不会和
# 系统或运维自己的配置互相覆盖。
readonly SYSCTL_PATH="/etc/sysctl.d/99-porttransit.conf"

readonly RED=$'\033[31m'; readonly GREEN=$'\033[32m'; readonly YELLOW=$'\033[33m'
readonly BLUE=$'\033[34m'; readonly BOLD=$'\033[1m'; readonly RESET=$'\033[0m'

# 输出统一走 stderr，这样 stdout 可以留给机器读取的内容。
info()  { printf '%s==>%s %s\n' "${BLUE}${BOLD}" "${RESET}" "$*" >&2; }
ok()    { printf '%s✔%s %s\n' "${GREEN}" "${RESET}" "$*" >&2; }
warn()  { printf '%s!%s %s\n' "${YELLOW}" "${RESET}" "$*" >&2; }
die()   { printf '%s✘%s %s\n' "${RED}" "${RESET}" "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "需要 root 权限。请使用：sudo bash $0 $*"
  fi
}

detect_os() {
  [[ -r /etc/os-release ]] || die "无法读取 /etc/os-release，不支持的系统"
  # shellcheck disable=SC1091
  . /etc/os-release

  case "${ID:-}" in
    debian|ubuntu) ;;
    *) die "仅支持 Debian 与 Ubuntu，当前系统是 ${ID:-未知}" ;;
  esac

  ARCH="$(uname -m)"
  case "${ARCH}" in
    x86_64|amd64)   ARCH="amd64" ;;
    aarch64|arm64)  ARCH="arm64" ;;
    *) die "仅支持 amd64 与 arm64，当前架构是 ${ARCH}" ;;
  esac

  # 只有 systemd 主机才能注册服务；容器里通常没有，提前说清楚比安装到一半失败好。
  # 注意：这里必须做「功能性」检查而不是只看 systemctl 是否存在 —— WSL、Docker、
  # 各种精简容器里 systemctl 二进制都在，但 dbus 是死的，命令会以
  # "System has not been booted with systemd as init system" 失败。若只在
  # write_unit 里才炸，前面的二进制与配置都已经落盘，留下一个半装状态。
  if ! command -v systemctl >/dev/null 2>&1; then
    die "未检测到 systemd。本脚本需要 systemd；容器环境请使用 porttransit run 直接前台运行"
  fi
  if [[ "$(ps -p 1 -o comm= 2>/dev/null || true)" != "systemd" ]] \
     && [[ ! -d /run/systemd/system ]]; then
    die "systemd 未作为 init 运行（PID 1 是 $(ps -p 1 -o comm= 2>/dev/null || echo 未知)，且 /run/systemd/system 不存在）。
   本脚本需要真正由 systemd 引导的主机。容器 / WSL 请改用：
     porttransit init --mode server --config /etc/porttransit/config.json
     porttransit run  --config /etc/porttransit/config.json
   或直接使用 --status / --uninstall 等不依赖 systemd 的子命令。"
  fi

  ok "系统：${PRETTY_NAME:-${ID}} (${ARCH})"
}

install_deps() {
  info "安装依赖"
  export DEBIAN_FRONTEND=noninteractive

  # apt 在云镜像上偶尔会因为残留的锁失败，重试一次比直接报错更实用。
  if ! apt-get update -qq 2>/dev/null; then
    warn "apt-get update 失败，等待后重试一次"
    sleep 3
    apt-get update -qq || die "apt-get update 失败，请检查网络或软件源"
  fi

  local pkgs=(ca-certificates curl)
  # iptables 用来在安装后检查是否存在会挡住中转端口的规则。
  command -v iptables >/dev/null 2>&1 || pkgs+=(iptables)
  apt-get install -y -qq "${pkgs[@]}" >/dev/null 2>&1 || warn "部分依赖安装失败，继续尝试"
  ok "依赖就绪"
}

tune_kernel() {
  # 中转的两段线路都是跨国链路，必然有丢包。默认的 CUBIC 一遇到丢包就把
  # 拥塞窗口砍半，BBR 不这么做，所以在有丢包的链路上差距很明显。这是所有
  # 优化里投入产出比最高的一项。
  #
  # 实际参数与逐项读回校验都在二进制里的 `porttransit tune` 实现。这里刻意
  # 不重复一遍：两份清单一定会漂移，而漂移的表现是「脚本说调好了、程序说
  # 没调」这种最难排查的状态。
  [[ "${SKIP_TUNE}" -eq 1 ]] && { info "按要求跳过内核调优"; return; }

  info "内核网络调优"
  if ! "${BIN_PATH}" tune; then
    # 调优失败不影响中转本身，只是慢一些。
    warn "内核调优未完成；中转仍可正常使用（可稍后手动执行：${BIN_PATH} tune）"
  elif [[ -f "${SYSCTL_PATH}" ]]; then
    # 文件存在才说明真的有参数生效了。不能只看退出码：容器里所有参数都写不
    # 进去，命令仍然成功返回（这是刻意的，否则容器里会安装失败），此时打出
    # 「调优完成」就是在撒谎。
    ok "内核调优完成，已写入 ${SYSCTL_PATH}"
  else
    warn "内核参数不可写（容器环境？），本次未调优；中转仍可正常使用"
  fi
}

download_binary() {
  info "获取 ${BIN_NAME} 可执行文件"

  if [[ -n "${PORTTRANSIT_BINARY:-}" ]]; then
    [[ -f "${PORTTRANSIT_BINARY}" ]] || die "PORTTRANSIT_BINARY 指向的文件不存在：${PORTTRANSIT_BINARY}"
    install -m 0755 "${PORTTRANSIT_BINARY}" "${BIN_PATH}"
    ok "已使用本地文件：${PORTTRANSIT_BINARY}"
    return
  fi

  if [[ -n "${PORTTRANSIT_URL:-}" ]]; then
    local url="${PORTTRANSIT_URL}"
    info "从 ${url} 下载"
    curl -fsSL --retry 3 --connect-timeout 15 "${url}" -o "${BIN_PATH}.tmp" \
      || die "下载失败：${url}"
  else
    # 默认从项目的 GitHub Release 下载。版本号可以通过 PORTTRANSIT_VERSION 固定。
    #
    # 发行包的命名在历史上出现过两种写法（连字符与下划线），而 Release 页面
    # 上的文件名一旦发出去就不能改，所以这里按顺序逐个尝试而不是只赌一个。
    # 只试第一个会让一次改名把所有老安装脚本全部变成 404。
    local version="${PORTTRANSIT_VERSION:-latest}"
    local base="${PORTTRANSIT_REPO:-https://github.com/zhengwuji/duankouzhuanfa/releases}"
    local -a urls=()
    if [[ "${version}" == "latest" ]]; then
      urls+=(
        "${base}/latest/download/${BIN_NAME}-linux-${ARCH}.tar.gz"
        "${base}/latest/download/${BIN_NAME}_linux_${ARCH}.tar.gz"
      )
    else
      urls+=(
        "${base}/download/${version}/${BIN_NAME}-${version}-linux-${ARCH}.tar.gz"
        "${base}/download/${version}/${BIN_NAME}-linux-${ARCH}.tar.gz"
        "${base}/download/${version}/${BIN_NAME}_linux_${ARCH}.tar.gz"
      )
    fi

    local url="" fetched=0
    for candidate in "${urls[@]}"; do
      info "从 ${candidate} 下载"
      if curl -fsSL --retry 2 --connect-timeout 15 "${candidate}" -o "${BIN_PATH}.tar.gz"; then
        url="${candidate}"
        fetched=1
        break
      fi
      rm -f "${BIN_PATH}.tar.gz"
    done

    if [[ "${fetched}" -ne 1 ]]; then
      die "下载失败，已尝试：
$(printf '  %s\n' "${urls[@]}")
请检查网络，或用 PORTTRANSIT_URL 指定下载地址，或把二进制放到本机后用 PORTTRANSIT_BINARY 指定路径"
    fi
    # 压缩包内应当只有一个文件；解压到临时目录再安装，避免覆盖正在使用的二进制。
    local tmpdir
    tmpdir="$(mktemp -d)"
    tar -xzf "${BIN_PATH}.tar.gz" -C "${tmpdir}" || { rm -rf "${tmpdir}" "${BIN_PATH}.tar.gz"; die "解压失败"; }
    local extracted
    extracted="$(find "${tmpdir}" -type f -name "${BIN_NAME}*" -perm -u+x | head -n1)"
    [[ -n "${extracted}" ]] || extracted="$(find "${tmpdir}" -type f -name "${BIN_NAME}*" | head -n1)"
    [[ -n "${extracted}" ]] || { rm -rf "${tmpdir}" "${BIN_PATH}.tar.gz"; die "压缩包中未找到 ${BIN_NAME} 可执行文件"; }
    mv "${extracted}" "${BIN_PATH}.tmp"
    rm -rf "${tmpdir}" "${BIN_PATH}.tar.gz"
  fi

  chmod 0755 "${BIN_PATH}.tmp"
  mv "${BIN_PATH}.tmp" "${BIN_PATH}"
  ok "已安装到 ${BIN_PATH}"
}

create_dirs() {
  info "创建目录"
  install -d -m 0750 "${CONFIG_DIR}"
  install -d -m 0750 "${CONFIG_DIR}/certs"
  install -d -m 0750 "${DATA_DIR}"
  install -d -m 0750 "${LOG_DIR}"
  ok "目录就绪"
}

generate_config() {
  if [[ -f "${CONFIG_PATH}" && "${FORCE_CONFIG}" -ne 1 ]]; then
    warn "配置已存在，保留现有配置：${CONFIG_PATH}"
    return
  fi

  # 只有真的走到 init 才会有新密码被打印出来。show_result 依赖这个标志决定
  # 要不要提醒「密码只显示一次」：保留既有配置时没有任何密码出现在屏幕上，
  # 却警告用户保存一个并不存在的密码，会让人以为自己漏看了。
  CONFIG_GENERATED=1

  info "生成中转配置"
  local args=(
    init
    --config "${CONFIG_PATH}"
    --mode server
    --transport "${TRANSPORT}"
    --force
  )
  [[ -n "${LISTEN}" ]] && args+=(--listen "${LISTEN}")
  [[ -n "${LINE_NAME}" ]] && args+=(--name "${LINE_NAME}")
  [[ -n "${ADMIN_PASSWORD}" ]] && args+=(--admin-password "${ADMIN_PASSWORD}")

  "${BIN_PATH}" "${args[@]}"

  chmod 0600 "${CONFIG_PATH}"
  ok "配置已写入 ${CONFIG_PATH}"
}

write_unit() {
  info "注册系统服务"

  # 需要绑定 1024 以下端口时才有 CAP_NET_BIND_SERVICE 的意义，但仍然保留，
  # 因为很多主机把 443 留给中转。
  cat > "${UNIT_PATH}" <<EOF
[Unit]
Description=PortTransit 端口转发 / 中转服务
Documentation=https://github.com/zhengwuji/duankouzhuanfa
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BIN_PATH} run --config ${CONFIG_PATH}
Restart=always
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
ReadWritePaths=${DATA_DIR} ${LOG_DIR} ${CONFIG_DIR}
# systemd sets no HOME, and the console's remote-deployment feature stores the
# SSH host keys it trusts under $HOME/.ssh/known_hosts. Without this the store
# has no writable home to live in, and the service runs with a working directory
# of "/" under ProtectSystem=strict. The data directory is already writable and
# is the right place for a daemon's own state, so it doubles as the home.
Environment=HOME=${DATA_DIR}
StandardOutput=append:${LOG_DIR}/porttransit.log
StandardError=append:${LOG_DIR}/porttransit.log

[Install]
WantedBy=multi-user.target
EOF

  chmod 0644 "${UNIT_PATH}"
  systemctl daemon-reload
  systemctl enable "${BIN_NAME}" >/dev/null 2>&1 || warn "设置开机自启失败"
  ok "服务已注册"
}

start_service() {
  info "启动服务"
  systemctl restart "${BIN_NAME}"
  sleep 1

  if ! systemctl is-active --quiet "${BIN_NAME}"; then
    echo >&2
    warn "服务启动失败，最近日志："
    journalctl -u "${BIN_NAME}" -n 30 --no-pager >&2 || true
    die "启动失败。可用 journalctl -u ${BIN_NAME} -f 查看完整日志"
  fi
  ok "服务已启动"
}

open_firewall() {
  local port="$1"
  info "检查防火墙"

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw allow "${port}/tcp" >/dev/null 2>&1 && ok "ufw 已放行 ${port}/tcp" || warn "ufw 放行失败，请手动执行：ufw allow ${port}/tcp"
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1 && ok "firewalld 已放行 ${port}/tcp" || warn "firewalld 放行失败"
  fi

  # 只提示不修改：在不知道主机策略的情况下直接插入 iptables 规则，
  # 有可能把操作者自己锁在外面，那比端口不通严重得多。
  if command -v iptables >/dev/null 2>&1; then
    if iptables -S INPUT 2>/dev/null | grep -qE 'DROP|REJECT'; then
      warn "检测到 iptables 存在 DROP/REJECT 规则；若客户端连不上，请手动放行 ${port}/tcp"
    fi
  fi
}

show_result() {
  echo >&2
  printf '%s╭──────────────────────────────────────────────╮%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
  printf '%s│            PortTransit 安装完成              │%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
  printf '%s╰──────────────────────────────────────────────╯%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
  echo >&2
  printf '  %s服务状态%s  systemctl status %s\n' "${BOLD}" "${RESET}" "${BIN_NAME}" >&2
  printf '  %s实时日志%s  journalctl -u %s -f\n' "${BOLD}" "${RESET}" "${BIN_NAME}" >&2
  printf '  %s配置文件%s  %s\n' "${BOLD}" "${RESET}" "${CONFIG_PATH}" >&2
  printf '  %s查看凭据%s  %s show-credentials\n' "${BOLD}" "${RESET}" "${BIN_PATH}" >&2
  printf '  %s重置密码%s  %s reset-password\n' "${BOLD}" "${RESET}" "${BIN_PATH}" >&2
  printf '  %s彻底卸载%s  bash %s --uninstall\n' "${BOLD}" "${RESET}" "$0" >&2
  echo >&2

  if [[ "${CONFIG_GENERATED}" -eq 1 ]]; then
    warn "上面的管理员密码只显示一次，请立即保存。"
  else
    # 既有配置被保留，本次没有生成也没有打印任何密码。指一条能查到凭据的
    # 明路，而不是让用户去找一个从未出现在屏幕上的密码。
    printf '  %s管理员密码沿用原配置，可用上面的「查看凭据」或 reset-password 获取。%s\n' "${BOLD}" "${RESET}" >&2
  fi
}

do_install() {
  require_root "$@"
  detect_os
  install_deps
  create_dirs
  download_binary
  generate_config
  write_unit
  # 放在启动之前：服务起来时就已经跑在调优后的内核参数上了。
  tune_kernel
  start_service

  # 从生成的配置里读出监听端口，用于防火墙放行与结果展示。
  local port
  port="$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"[^:]*:\([0-9]\+\).*/\1/p' "${CONFIG_PATH}" | head -n1)"
  [[ -n "${port}" ]] && open_firewall "${port}"

  show_result
}

do_uninstall() {
  require_root "$@"

  # 卸载会删掉配置与数据，而 --uninstall 只有两个词，手滑的代价是不可逆的。
  # Go 侧的 porttransit uninstall 一直要求输入 yes，这里保持一致；
  # 自动化场景用 --yes 跳过。
  if [[ "${ASSUME_YES}" -eq 0 ]]; then
    echo >&2
    warn "即将彻底卸载 PortTransit："
    echo "    删除服务单元 ${UNIT_PATH}" >&2
    echo "    删除可执行文件 ${BIN_PATH}" >&2
    if [[ "${KEEP_DATA}" -eq 1 ]]; then
      echo "    保留 ${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR}" >&2
    else
      echo "    删除 ${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR}（含全部配置与数据）" >&2
    fi
    echo >&2
    if [[ ! -t 0 ]]; then
      die "非交互环境下请显式加 --yes 确认卸载"
    fi
    printf '确认继续？输入 yes 回车：' >&2
    local answer=""
    read -r answer || true
    if [[ "${answer}" != "yes" ]]; then
      die "已取消"
    fi
  fi

  info "停止并删除服务"
  systemctl stop "${BIN_NAME}" 2>/dev/null || true
  systemctl disable "${BIN_NAME}" 2>/dev/null || true

  # 服务停止后仍可能有残留进程持有端口，显式结束它，
  # 否则重新安装会因为端口被占用而失败。
  pkill -f "${BIN_PATH} run" 2>/dev/null || true
  sleep 1

  rm -f "${UNIT_PATH}"
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed "${BIN_NAME}" 2>/dev/null || true
  ok "服务已删除"

  info "删除可执行文件"
  rm -f "${BIN_PATH}"
  ok "已删除 ${BIN_PATH}"

  # 删掉调优文件，否则重装或重启后这些参数会一直被应用，而用户以为已经卸载干净。
  # 当前正在生效的值只能等重启才会回到内核默认——sysctl 无法"撤销"到未知的旧值，
  # 硬改回某个猜测值反而可能破坏系统或运维自己的设置。这一点如实告知。
  #
  # 优先用二进制自己的子命令，保持与安装时的实现同源。
  if [[ -x "${BIN_PATH}" ]] && "${BIN_PATH}" tune --revert >/dev/null 2>&1; then
    ok "已删除内核调优配置 ${SYSCTL_PATH}"
  elif [[ -f "${SYSCTL_PATH}" ]]; then
    rm -f "${SYSCTL_PATH}"
    ok "已删除内核调优配置 ${SYSCTL_PATH}"
    warn "当前运行中的内核参数仍是调优值，重启后恢复系统默认"
  fi

  if [[ "${KEEP_DATA}" -eq 1 ]]; then
    warn "按要求保留配置与数据：${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR}"
  else
    info "删除配置与数据"
    rm -rf "${CONFIG_DIR}" "${DATA_DIR}" "${LOG_DIR}"
    ok "已删除 ${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR}"
  fi

  echo >&2
  ok "PortTransit 已彻底卸载"
}

do_reset_password() {
  require_root "$@"
  [[ -x "${BIN_PATH}" ]] || die "未找到 ${BIN_PATH}，请先安装"
  [[ -f "${CONFIG_PATH}" ]] || die "未找到 ${CONFIG_PATH}"

  # The password must be forwarded explicitly. `$@` inside a function is the
  # FUNCTION's arguments, and this one is called with none — so forwarding "$@"
  # silently dropped the user's --admin-password and generated a random one
  # instead, which then scrolled past as if it were what they asked for.
  local args=(reset-password --config "${CONFIG_PATH}")
  [[ -n "${ADMIN_PASSWORD}" ]] && args+=(--password "${ADMIN_PASSWORD}")
  [[ -n "${ADMIN_USERNAME}" ]] && args+=(--username "${ADMIN_USERNAME}")
  "${BIN_PATH}" "${args[@]}"

  if systemctl is-active --quiet "${BIN_NAME}" 2>/dev/null; then
    info "重启服务以生效"
    systemctl restart "${BIN_NAME}"
    ok "服务已重启"
  fi
}

do_status() {
  if [[ -x "${BIN_PATH}" && -f "${CONFIG_PATH}" ]]; then
    "${BIN_PATH}" status --config "${CONFIG_PATH}" || true
  else
    warn "尚未安装，或配置文件不存在"
  fi
  echo >&2
  systemctl status "${BIN_NAME}" --no-pager 2>/dev/null || warn "服务未运行"
}

usage() {
  cat >&2 <<'EOF'
PortTransit 一键脚本

用法：
  bash install.sh [选项]

安装选项：
  --transport <名称>   中转协议，默认 tls
                       可选：tls / reality / vless / vmess / trojan /
                             shadowsocks / ws（WebSocket）/ httpupgrade /
                             http（HTTP CONNECT）/ socks5 / direct
  --port <端口>        中转监听端口，默认 8443
  --listen <地址>      完整监听地址，例如 0.0.0.0:443（优先于 --port）
  --name <名称>        线路名称，例如「上海中转」
  --admin-password <密码>  网页控制台管理员密码（默认随机生成）
  --admin-username <用户名> 网页控制台管理员用户名（默认 admin）
  --force-config       覆盖已存在的配置
  --skip-tune          跳过内核网络调优（BBR 等），不写 /etc/sysctl.d

操作：
  --uninstall          彻底卸载（删除服务、二进制、配置与数据）
  --keep-data          卸载时保留配置与数据
  --yes, -y            不询问，直接确认卸载（非交互环境必须加）
  --reset-password     重置管理后台密码
  --status             查看运行状态

环境变量：
  PORTTRANSIT_BINARY   使用本机已有的可执行文件而不是下载
  PORTTRANSIT_URL      指定下载地址
  PORTTRANSIT_VERSION  指定版本，默认 latest
  PORTTRANSIT_REPO     Release 仓库地址

示例：
  sudo bash install.sh
  sudo bash install.sh --transport reality --port 443
  sudo bash install.sh --uninstall
EOF
}

# ------------------------------------------------------------------ 参数解析

TRANSPORT="tls"
PORT=""
LISTEN=""
LINE_NAME=""
ADMIN_PASSWORD=""
ADMIN_USERNAME=""
FORCE_CONFIG=0
CONFIG_GENERATED=0
KEEP_DATA=0
ASSUME_YES=0
SKIP_TUNE=0
ACTION="install"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --transport)       TRANSPORT="${2:?--transport 需要一个值}"; shift 2 ;;
    --port)            PORT="${2:?--port 需要一个值}"; shift 2 ;;
    --listen)          LISTEN="${2:?--listen 需要一个值}"; shift 2 ;;
    --name)            LINE_NAME="${2:?--name 需要一个值}"; shift 2 ;;
    --admin-password)  ADMIN_PASSWORD="${2:?--admin-password 需要一个值}"; shift 2 ;;
    --admin-username)  ADMIN_USERNAME="${2:?--admin-username 需要一个值}"; shift 2 ;;
    --force-config)    FORCE_CONFIG=1; shift ;;
    --skip-tune)       SKIP_TUNE=1; shift ;;
    --uninstall)       ACTION="uninstall"; shift ;;
    --keep-data)       KEEP_DATA=1; shift ;;
    --yes|-y)          ASSUME_YES=1; shift ;;
    --reset-password)  ACTION="reset-password"; shift ;;
    --status)          ACTION="status"; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "未知参数：$1（使用 --help 查看用法）" ;;
  esac
done

# --port 只是 --listen 的简写，两者都给出时以 --listen 为准。
if [[ -z "${LISTEN}" && -n "${PORT}" ]]; then
  LISTEN="0.0.0.0:${PORT}"
fi

case "${ACTION}" in
  install)        do_install ;;
  uninstall)      do_uninstall ;;
  reset-password) do_reset_password ;;
  status)         do_status ;;
  *)              die "未知操作：${ACTION}" ;;
esac
