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

# The path this script was read from, or empty when it came from a pipe.
#
# The documented way to run this installer is `curl … | bash -s -- …`, and in
# that form $0 is literally "bash". Printing it produced the instruction
# "bash bash --uninstall", which cannot work — so the self path is only kept
# when the script really is a file on disk.
SCRIPT_PATH=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_PATH="${BASH_SOURCE[0]}"
fi

# Where a fresh copy of this script can be fetched. Only used in the piped
# form, where there is no local file to point at.
readonly SCRIPT_URL="${PORTTRANSIT_SCRIPT_URL:-https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/install.sh}"

# 输出统一走 stderr，这样 stdout 可以留给机器读取的内容。
info()  { printf '%s==>%s %s\n' "${BLUE}${BOLD}" "${RESET}" "$*" >&2; }
ok()    { printf '%s✔%s %s\n' "${GREEN}" "${RESET}" "$*" >&2; }
warn()  { printf '%s!%s %s\n' "${YELLOW}" "${RESET}" "$*" >&2; }
die()   { printf '%s✘%s %s\n' "${RED}" "${RESET}" "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    # $0 is "bash" in the documented `curl … | bash -s -- …` form, so the hint
    # is built from the real script path when there is one.
    if [[ -n "${SCRIPT_PATH}" ]]; then
      die "需要 root 权限。请使用：sudo bash ${SCRIPT_PATH} $*"
    fi
    die "需要 root 权限。请用 sudo 运行，例如：curl -fsSL ${SCRIPT_URL} | sudo bash -s -- $*"
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
    --webui-listen "${WEBUI_LISTEN}"
  )
  [[ -n "${LISTEN}" ]] && args+=(--listen "${LISTEN}")
  [[ -n "${LINE_NAME}" ]] && args+=(--name "${LINE_NAME}")
  [[ -n "${ADMIN_USERNAME}" ]] && args+=(--admin-user "${ADMIN_USERNAME}")
  [[ -n "${ADMIN_PASSWORD}" ]] && args+=(--admin-password "${ADMIN_PASSWORD}")
  [[ "${WEBUI_ALLOW_REMOTE}" -eq 1 ]] && args+=(--webui-allow-remote)

  # init 只在这一次运行里打印明文密码（配置里只存 bcrypt 哈希），所以输出必须
  # 先接住再转发：既让用户看到完整凭据，也让脚本能把它提取出来，在最后的
  # 「安装完成」横幅里连同控制台地址一起显示 —— 否则用户要在一屏滚动输出里
  # 自己找那一行，而这行错过就再也拿不到了。
  local out
  if ! out="$("${BIN_PATH}" "${args[@]}" 2>&1)"; then
    printf '%s\n' "${out}" >&2
    die "生成配置失败"
  fi
  printf '%s\n' "${out}" >&2

  ADMIN_PASSWORD_SHOWN="$(printf '%s\n' "${out}" | sed -n 's/^管理员密码：//p' | head -n1)"
  ADMIN_USERNAME_SHOWN="$(printf '%s\n' "${out}" | sed -n 's/^管理员用户名：//p' | head -n1)"

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

# open_firewall 的标题只打一次。
#
# 它现在被调用两次（中转端口与控制台端口），每次都打标题会让输出出现两行
# 相同的「检查防火墙」，看起来像脚本跑了两次。
FIREWALL_ANNOUNCED=0
ensure_firewall_open() {
  local port="$1"
  if [[ "${FIREWALL_ANNOUNCED}" -eq 0 ]]; then
    info "检查防火墙"
    FIREWALL_ANNOUNCED=1
  fi
  open_firewall "${port}"
}

show_result() {
  echo >&2
  printf '%s╭──────────────────────────────────────────────╮%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
  printf '%s│            PortTransit 安装完成              │%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
  printf '%s╰──────────────────────────────────────────────╯%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
  echo >&2

  # 先给控制台入口：这是安装完最想立刻打开的东西。地址由二进制的
  # show-console 算出来（通配绑定会换成主机自己的出口地址），因为
  # "http://0.0.0.0:8787" 不是一个能打开的地址。
  #
  # `|| true` 是必要的：脚本开了 pipefail，show-console 是较新版本才有的
  # 子命令，老二进制会让管道非零并触发 ERR trap。横幅显示不出地址可以接受，
  # 因此中断整个安装不行。
  local console_url="" console_user="" console_listen=""
  local line
  while IFS= read -r line; do
    case "${line}" in
      url=*)      console_url="${line#url=}" ;;
      username=*) console_user="${line#username=}" ;;
      listen=*)   console_listen="${line#listen=}" ;;
    esac
  done < <("${BIN_PATH}" show-console --config "${CONFIG_PATH}" 2>/dev/null || true)

  # 旧版二进制没有 show-console。退回直接读配置，这样横幅至少能给出监听地址
  # 和账号（用户名来自配置，不依赖二进制），而不是干脆不显示控制台。
  if [[ -z "${console_listen}" ]]; then
    console_listen="$(config_webui_listen)"
  fi
  if [[ -z "${console_user}" ]]; then
    console_user="$(config_webui_field "username")"
  fi
  if [[ -z "${console_url}" && -n "${console_listen}" ]]; then
    console_url="http://${console_listen}"
  fi

  if [[ -n "${console_url}" ]]; then
    printf '  %s网页控制台%s  %s%s%s\n' "${BOLD}" "${RESET}" "${GREEN}" "${console_url}" "${RESET}" >&2
    [[ -n "${console_user}" ]] && printf '  %s管理员账号%s  %s\n' "${BOLD}" "${RESET}" "${console_user}" >&2
    if [[ -n "${ADMIN_PASSWORD_SHOWN}" ]]; then
      printf '  %s管理员密码%s  %s%s%s\n' "${BOLD}" "${RESET}" "${GREEN}" "${ADMIN_PASSWORD_SHOWN}" "${RESET}" >&2
    fi
    echo >&2

    if [[ "${console_listen}" == 127.0.0.1:* || "${console_listen}" == localhost:* || "${console_listen}" == "[::1]:"* ]]; then
      # 只监听本机时上面那个 URL 从外部打不开。直接把能用的命令给出来，
      # 而不是让用户自己意识到这一点。
      local cport="${console_listen##*:}"
      printf '  %s控制台只监听本机%s，从外部浏览器打开需要一条 SSH 隧道：\n' "${BOLD}" "${RESET}" >&2
      printf '      ssh -N -L %s:127.0.0.1:%s root@<服务器地址>\n' "${cport}" "${cport}" >&2
      printf '      然后打开 %s\n' "${console_url}" >&2
      printf '      想直接用 服务器IP:%s 打开：进入管理菜单，选 8 改成外网可访问。\n' "${cport}" >&2
      echo >&2
    else
      # 公网可访问就必须说清楚风险：这个后台能改所有线路、还能通过 SSH
      # 往别的服务器装服务端。提醒用户改密码，并说明已有防爆破。
      warn "控制台可被公网访问（${console_listen}），请立即修改管理员密码。"
      printf '      登录失败会递增锁定：前 5 次不惩罚，之后每次翻倍，最长锁 15 分钟。\n' >&2
      printf '      改成只监听本机：管理菜单选 8（或重跑安装加 --webui-listen 127.0.0.1:8787）\n' >&2
      echo >&2
    fi
  fi

  printf '  %s服务状态%s  systemctl status %s\n' "${BOLD}" "${RESET}" "${BIN_NAME}" >&2
  printf '  %s实时日志%s  journalctl -u %s -f\n' "${BOLD}" "${RESET}" "${BIN_NAME}" >&2
  printf '  %s配置文件%s  %s\n' "${BOLD}" "${RESET}" "${CONFIG_PATH}" >&2
  printf '  %s控制台信息%s  %s show-console\n' "${BOLD}" "${RESET}" "${BIN_PATH}" >&2
  printf '  %s查看凭据%s  %s show-credentials\n' "${BOLD}" "${RESET}" "${BIN_PATH}" >&2
  printf '  %s重置密码%s  %s reset-password\n' "${BOLD}" "${RESET}" "${BIN_PATH}" >&2
  if [[ -n "${SCRIPT_PATH}" ]]; then
    printf '  %s彻底卸载%s  bash %s --uninstall\n' "${BOLD}" "${RESET}" "${SCRIPT_PATH}" >&2
  else
    # Piped install: there is no script file on disk to re-run, and $0 is
    # "bash". The installer's own binary is the reliable way out — it carries
    # the same uninstall logic the script delegates to.
    printf '  %s彻底卸载%s  %s uninstall --yes\n' "${BOLD}" "${RESET}" "${BIN_PATH}" >&2
    printf '              或用脚本卸载：curl -fsSL %s | bash -s -- --uninstall\n' "${SCRIPT_URL}" >&2
  fi
  # 提示菜单的存在：用户的习惯是重跑那条带参数的安装命令，而带参数时不进
  # 菜单（否则自动化脚本会被卡住），所以必须主动告诉他们怎么打开。
  if [[ -n "${SCRIPT_PATH}" ]]; then
    printf '  %s管理菜单%s  bash %s --menu\n' "${BOLD}" "${RESET}" "${SCRIPT_PATH}" >&2
  else
    printf '  %s管理菜单%s  curl -fsSL %s | bash -s -- --menu\n' \
      "${BOLD}" "${RESET}" "${SCRIPT_URL}" >&2
  fi
  echo >&2

  if [[ "${CONFIG_GENERATED}" -eq 1 ]]; then
    warn "上面的管理员密码只显示一次，请立即保存。"
  else
    # 既有配置被保留，本次没有生成也没有打印任何密码。指一条能查到凭据的
    # 明路，而不是让用户去找一个从未出现在屏幕上的密码。
    printf '  %s管理员密码沿用原配置；如需换一个，执行上面的 reset-password。%s\n' \
      "${BOLD}" "${RESET}" >&2
  fi
}

do_install() {
  require_root "$@"
  detect_os
  install_deps
  create_dirs
  download_binary
  generate_config

  # 配置已存在时上面的 init 不会执行，--webui-listen 会被静默忽略 —— 用户会
  # 以为已经改成外网可访问，实际控制台还留在老地址上。显式给了参数就必须真的
  # 改掉，而且只改这一个字段：线路与凭据保持原样。
  #
  # 没有显式给参数时什么都不做：沿用中的监听地址是运维自己定的（可能出于安全
  # 考虑），绝不能被脚本的默认值悄悄覆盖成对外网开放。
  if [[ "${WEBUI_LISTEN_GIVEN}" -eq 1 && "${CONFIG_GENERATED}" -eq 0 ]]; then
    info "更新控制台监听地址"
    if ! set_webui_listen "${WEBUI_LISTEN}"; then
      warn "控制台监听地址未更新（当前安装的版本可能不支持 set-console）"
      warn "重跑本脚本即可更新到最新版；也可手动编辑 ${CONFIG_PATH} 里的 webui.listen 与 webui.allowRemote"
    fi
  fi
  write_unit
  # 放在启动之前：服务起来时就已经跑在调优后的内核参数上了。
  tune_kernel
  start_service

  # 从生成的配置里读出监听端口，用于防火墙放行与结果展示。
  local port
  port="$(sed -n 's/.*"listen"[[:space:]]*:[[:space:]]*"[^:]*:\([0-9]\+\).*/\1/p' "${CONFIG_PATH}" | head -n1)"
  [[ -n "${port}" ]] && ensure_firewall_open "${port}"

  # 控制台绑定在非回环地址时也要放行，否则装完打印的公网链接根本连不上，
  # 用户会以为是控制台坏了。端口从 show-console 读，避免与配置漂移。
  #
  # `|| true` 不是可有可无的：脚本开了 pipefail，而 show-console 是较新版本
  # 才有的子命令 —— 老版本二进制（或任何查询失败）会让整条管道非零，触发
  # ERR trap 直接中断安装。查不到就不放行控制台端口，不该让安装失败。
  local webui_listen webui_port
  webui_listen="$("${BIN_PATH}" show-console --config "${CONFIG_PATH}" 2>/dev/null \
    | sed -n 's/^listen=//p' | head -n1 || true)"
  if [[ -n "${webui_listen}" && "${webui_listen}" != 127.0.0.1:* \
     && "${webui_listen}" != localhost:* && "${webui_listen}" != "[::1]:"* ]]; then
    webui_port="${webui_listen##*:}"
    [[ -n "${webui_port}" ]] && ensure_firewall_open "${webui_port}"
  fi

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
    # 必须问终端，不能问 stdin。
    #
    # 文档里的主要用法是 `curl … | bash`，那时 stdin 就是脚本自身：从 stdin
    # 读会把后面的脚本内容当成回答（而且无论答什么都可能正好是 "yes"），
    # 卸载确认就形同虚设。菜单路径下更糟 —— 它会把脚本剩余部分吃掉，
    # 菜单直接死掉。
    if [[ ! -r /dev/tty ]]; then
      die "非交互环境下请显式加 --yes 确认卸载"
    fi
    if ! confirm "确认继续？"; then
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

# ------------------------------------------------------------------ 交互菜单

# 能否向用户提问。
#
# `curl … | bash` 是本脚本文档里的主要用法，那时 **stdin 是脚本自身**：任何
# `read` 都会吃掉脚本后面的内容，而不是读用户的键盘。所以提问一律走 /dev/tty。
# 没有终端时（CI、cron、Ansible、重定向）不进菜单，直接按参数执行。
has_terminal() {
  [[ -r /dev/tty && -w /dev/tty ]] || return 1
  # 管道运行时 stdout/stderr 仍然连着终端，这是区分「有人在看」的依据。
  [[ -t 1 || -t 2 ]] || return 1
  return 0
}

# read_line <提示语>：从终端读一行并回显在 stdout。
read_line() {
  local prompt="$1" answer=""
  printf '%s' "${prompt}" >&2
  read -r answer < /dev/tty || answer=""
  printf '%s' "${answer}"
}

# read_secret <提示语>：不回显地读一行（密码用）。
read_secret() {
  local prompt="$1" answer=""
  printf '%s' "${prompt}" >&2
  read -rs answer < /dev/tty || answer=""
  printf '\n' >&2
  printf '%s' "${answer}"
}

# confirm <问题>：只有输入 yes 才返回真。
confirm() {
  local answer
  answer="$(read_line "$1（输入 yes 确认）：")"
  [[ "${answer}" == "yes" ]]
}

# config_webui_field <字段名>：不依赖二进制、直接从配置里读控制台信息。
#
# show-console 是较新版本才有的子命令。装了旧版二进制的机器上，菜单仍要能
# 说出控制台在哪个地址，否则会显示成「未启用」—— 那是错的，会让人以为控制台
# 被关掉了。
#
# 配置是格式化过的 JSON，"webui" 与 "listen" 不在同一行，所以不能用单行 sed
# 正则跨行匹配。这里先截出 webui 那一段再取字段。不用 python3：精简镜像上
# 未必有，而安装脚本不该因此多一个依赖。
config_webui_field() {
  local field="$1"
  sed -n '/"webui"[[:space:]]*:/,/^[[:space:]]*}/p' "${CONFIG_PATH}" 2>/dev/null \
    | sed -n "s/.*\"${field}\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
    | head -n1 || true
}

config_webui_listen() {
  config_webui_field "listen"
}

# set_webui_listen <地址>：把控制台监听地址写进现有配置，其余字段一个不动。
#
# 已经装过的机器上，generate_config 会原样保留配置（那正是它该做的：重跑安装
# 不该动线路和凭据），所以重跑时给的 --webui-listen 曾经被静默忽略：用户看到
# 「安装完成」，控制台却还在老地址上。改这一步交给二进制的 set-console ——
# 它加载、校验、原子写入，密码与线路凭据都不碰；直接 sed 改 JSON 则绕过了
# 校验，改错一个字段的后果是服务起不来。
set_webui_listen() {
  local addr="$1"
  local args=(set-console --config "${CONFIG_PATH}" --listen "${addr}")
  case "${addr}" in
    127.0.0.1:*|localhost:*|"[::1]:"*) ;;
    *) args+=(--allow-remote) ;;
  esac
  "${BIN_PATH}" "${args[@]}" >&2
}

# menu_summary 打印当前状态，让用户在选之前知道自己面对的是什么。
menu_summary() {
  local version service enabled lines console_url

  version="$("${BIN_PATH}" version 2>/dev/null | head -n1 || true)"
  [[ -n "${version}" ]] || version="未安装"

  service="$(systemctl is-active "${BIN_NAME}" 2>/dev/null || true)"
  enabled="$(systemctl is-enabled "${BIN_NAME}" 2>/dev/null || true)"
  [[ -n "${service}" ]] || service="未运行"
  [[ -n "${enabled}" ]] || enabled="未启用"

  # grep -c 在匹配数为 0 时既打印 "0" 又返回非零，所以不能写成 `|| echo 0`：
  # 那样会得到两行 "0"，打印出来是个换行。用管道接 awk 取第一个数字。
  lines="$(grep -c '"transport"' "${CONFIG_PATH}" 2>/dev/null | head -n1 || true)"
  [[ -n "${lines}" ]] || lines=0

  console_url="$("${BIN_PATH}" show-console --config "${CONFIG_PATH}" 2>/dev/null \
    | sed -n 's/^url=//p' | head -n1 || true)"
  if [[ -z "${console_url}" ]]; then
    # 旧版二进制没有 show-console，退回到直接读配置。
    local listen
    listen="$(config_webui_listen)"
    if [[ -n "${listen}" ]]; then
      console_url="http://${listen}"
      case "${listen}" in
        0.0.0.0:*|":*"|"[::]:"*) console_url="http://${listen#*:}（监听所有网卡）" ;;
      esac
    fi
  fi
  [[ -n "${console_url}" ]] || console_url="未启用"

  printf '  当前状态\n' >&2
  printf '    版本      %s\n' "${version}" >&2
  printf '    服务      %s / %s\n' "${service}" "${enabled}" >&2
  printf '    中转线路  %s 条\n' "${lines}" >&2
  printf '    控制台    %s\n' "${console_url}" >&2
}

# do_console_access：菜单里的「控制台访问地址（外网 / 仅本机）」。
#
# 装完之后第二常见的事就是这件：安装时沿用的旧配置里控制台只监听本机，想在
# 浏览器里直接用 服务器IP:端口 打开，却只能去翻配置文件手改 JSON —— 而手改
# JSON 一旦漏掉 allowRemote，服务下次启动会直接拒绝启动。
#
# 只改监听地址这一个字段：线路、PSK、控制台密码全部保持原样。重跑 init 也能
# 达到目的，但那会重新生成凭据，把所有已经配好的客户端打回原点。
do_console_access() {
  local current new_listen choice port
  current="$(config_webui_listen)"
  [[ -n "${current}" ]] || current="未知"

  info "控制台访问地址"
  printf '  当前监听：%s\n' "${current}" >&2
  echo >&2
  printf '  %s1%s) 外网可访问：0.0.0.0:8787（浏览器直接打开 http://<服务器IP>:8787）\n' "${BOLD}" "${RESET}" >&2
  printf '  %s2%s) 外网可访问：换个端口\n' "${BOLD}" "${RESET}" >&2
  printf '  %s3%s) 仅本机：127.0.0.1:8787（外部访问需要 SSH 隧道）\n' "${BOLD}" "${RESET}" >&2
  printf '  %s0%s) 取消\n' "${BOLD}" "${RESET}" >&2
  echo >&2

  choice="$(read_line '请选择 [0-3]：')"
  echo >&2

  case "${choice}" in
    1) new_listen="0.0.0.0:8787" ;;
    2)
      port="$(read_line '端口（1-65535，例如 8787）：')"
      if [[ ! "${port}" =~ ^[0-9]+$ ]] || (( 10#${port} < 1 || 10#${port} > 65535 )); then
        warn "端口无效：${port}"
        return
      fi
      new_listen="0.0.0.0:${port}"
      ;;
    3) new_listen="127.0.0.1:8787" ;;
    0|"") return ;;
    *) warn "无效选择：${choice}"; return ;;
  esac

  if ! set_webui_listen "${new_listen}"; then
    warn "修改失败：当前安装的版本可能不支持 set-console，选 1 更新到最新版后重试"
    return
  fi

  # 换了端口就要顺手放行，否则浏览器照样连不上，而用户以为已经开好了。
  case "${new_listen}" in
    127.0.0.1:*|localhost:*|"[::1]:"*) ;;
    *) ensure_firewall_open "${new_listen##*:}" ;;
  esac

  info "重启服务以生效"
  if systemctl restart "${BIN_NAME}" 2>/dev/null && sleep 1 \
     && systemctl is-active --quiet "${BIN_NAME}"; then
    ok "服务已重启"
  else
    warn "服务未能重启，最近日志："
    journalctl -u "${BIN_NAME}" -n 15 --no-pager 2>/dev/null || true
  fi
  echo >&2

  # 地址仍以 show-console 为准（通配绑定会换成主机自己的出口地址）。
  local url listen
  listen="$(config_webui_listen)"
  url="$("${BIN_PATH}" show-console --config "${CONFIG_PATH}" 2>/dev/null \
    | sed -n 's/^url=//p' | head -n1 || true)"
  [[ -n "${url}" ]] || url="http://${listen}"
  printf '  %s网页控制台%s  %s%s%s\n' "${BOLD}" "${RESET}" "${GREEN}" "${url}" "${RESET}" >&2

  case "${new_listen}" in
    127.0.0.1:*|localhost:*|"[::1]:"*)
      printf '  只监听本机，外部浏览器需要一条 SSH 隧道：\n' >&2
      printf '      ssh -N -L %s:127.0.0.1:%s root@<服务器地址>\n' "${new_listen##*:}" "${new_listen##*:}" >&2
      ;;
    *)
      warn "控制台现在可被公网访问，请确保管理员密码足够强。"
      printf '      想改回仅本机：再进本菜单选 8，然后选 3。\n' >&2
      ;;
  esac
}

# do_menu 是「重新运行脚本」时的入口。
#
# 装完之后最常见的动作是查看状态、取凭据、改密码，而不是重装。原来这些都
# 得记住对应的参数，用户只能靠翻 README 或反复试。菜单把这些摆出来，同时
# 保留所有参数路径不变 —— 带参数运行绝不会进菜单。
do_menu() {
  require_root "$@"

  if [[ ! -x "${BIN_PATH}" ]]; then
    warn "尚未安装，直接开始安装"
    do_install
    return
  fi

  while true; do
    echo >&2
    printf '%s╭──────────────────────────────────────────────╮%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
    printf '%s│           PortTransit 管理菜单               │%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
    printf '%s╰──────────────────────────────────────────────╯%s\n' "${GREEN}${BOLD}" "${RESET}" >&2
    echo >&2
    menu_summary
    echo >&2
    printf '  %s1%s) 安装 / 更新服务端（保留现有配置）\n' "${BOLD}" "${RESET}" >&2
    printf '  %s2%s) 查看运行状态\n' "${BOLD}" "${RESET}" >&2
    printf '  %s3%s) 查看中转凭据（客户端连接用）\n' "${BOLD}" "${RESET}" >&2
    printf '  %s4%s) 查看控制台地址与账号\n' "${BOLD}" "${RESET}" >&2
    printf '  %s5%s) 重置控制台密码\n' "${BOLD}" "${RESET}" >&2
    printf '  %s6%s) 重启服务\n' "${BOLD}" "${RESET}" >&2
    printf '  %s7%s) 彻底卸载\n' "${BOLD}" "${RESET}" >&2
    printf '  %s8%s) 控制台访问地址（外网 / 仅本机）\n' "${BOLD}" "${RESET}" >&2
    printf '  %s0%s) 退出\n' "${BOLD}" "${RESET}" >&2
    echo >&2

    local choice
    choice="$(read_line '请选择 [0-8]：')"
    echo >&2

    case "${choice}" in
      1) do_install ;;
      2) do_status ;;
      3)
        info "中转凭据"
        if ! "${BIN_PATH}" show-credentials --config "${CONFIG_PATH}" 2>/dev/null; then
          warn "当前安装的版本不支持 show-credentials，请先选 1 更新"
        fi
        echo >&2
        printf '  一条线路一条凭据；指定名称可看其它线路：\n' >&2
        printf '    %s show-credentials --name <线路名>\n' "${BIN_PATH}" >&2
        ;;
      4)
        info "控制台"
        # show-console 是较新版本才有的子命令。旧版会把它当成未知命令并打印
        # 整页帮助 —— 那看起来像菜单坏了。所以先探测，失败就退回直接读配置。
        if "${BIN_PATH}" show-console --config "${CONFIG_PATH}" 2>/dev/null; then
          :
        else
          local listen user
          listen="$(config_webui_listen)"
          user="$(config_webui_field "username")"
          if [[ -n "${listen}" ]]; then
            printf 'listen=%s\n' "${listen}" >&2
            printf 'url=http://%s\n' "${listen}" >&2
          fi
          [[ -n "${user}" ]] && printf 'username=%s\n' "${user}" >&2
          printf '\n' >&2
          warn "当前安装的版本不支持 show-console（上面的地址未经公网探测），选 1 可更新"
        fi
        echo >&2
        printf '  密码无法从配置读回（只存了哈希）。忘了就选 5 重设一个。\n' >&2
        ;;
      5)
        info "重置控制台密码"
        local pw pw2
        pw="$(read_secret '新密码（留空则随机生成，至少 8 位）：')"
        if [[ -n "${pw}" ]]; then
          # 输入不回显，打错了看不见，所以要求再输一遍。
          pw2="$(read_secret '再输入一次确认：')"
          if [[ "${pw}" != "${pw2}" ]]; then
            warn "两次输入不一致，未做修改"
            continue
          fi
          ADMIN_PASSWORD="${pw}"
        else
          ADMIN_PASSWORD=""
        fi
        do_reset_password
        ;;
      6)
        info "重启服务"
        systemctl restart "${BIN_NAME}" || warn "重启失败"
        sleep 1
        if systemctl is-active --quiet "${BIN_NAME}"; then
          ok "服务已重启"
        else
          warn "服务未在运行，最近日志："
          journalctl -u "${BIN_NAME}" -n 15 --no-pager 2>/dev/null || true
        fi
        ;;
      7)
        # do_uninstall 自己会再确认一次；这里不再问，避免连问两遍。
        do_uninstall
        return
        ;;
      8) do_console_access ;;
      0|"") return ;;
      *) warn "无效选择：${choice}" ;;
    esac
  done
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
  --webui-listen <地址>    网页控制台监听地址，默认 0.0.0.0:8787（公网可访问）
                           已经装过时只改现有配置里的这一项，线路与凭据不动
  --webui-allow-remote     确认允许控制台监听非回环地址（默认已开启）
                           只允许本机访问请用 --webui-listen 127.0.0.1:8787
  --force-config       覆盖已存在的配置（会重新生成全部凭据）
  --skip-tune          跳过内核网络调优（BBR 等），不写 /etc/sysctl.d

操作：
  --menu               打开管理菜单（安装/更新、状态、凭据、重置密码、卸载、
                       控制台访问地址）
                       已经装过时，不带任何参数重新运行脚本也会进这个菜单
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
  sudo bash install.sh --webui-listen 0.0.0.0:8787   # 已装过：让控制台可用 服务器IP:8787 直接打开
  sudo bash install.sh --webui-listen 127.0.0.1:8787 # 已装过：改回只允许本机
  sudo bash install.sh --menu
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
# 控制台默认监听 0.0.0.0，装完就能直接用公网地址打开。管理后台因此暴露在
# 网络上，只有密码一层防护 —— 因此登录失败会递增锁定（见 webui 的限流），
# 并且安装完成时会把地址、用户名、密码一起打印出来。
# 想只允许本机访问：--webui-listen 127.0.0.1:8787（外部访问走 SSH 隧道）。
WEBUI_LISTEN="0.0.0.0:8787"
WEBUI_ALLOW_REMOTE=1
# 用户是否显式给了 --webui-listen。
#
# 默认值本身就是对外网开放的，但那只适用于「这次生成配置」的情况：已经装过
# 的机器上配置文件会被原样保留，只有显式给参数时才去修改现有配置里的监听
# 地址 —— 不能因为默认值就把别人特意设成仅本机的控制台改成公开。
WEBUI_LISTEN_GIVEN=0
# init 打印出来的明文凭据，供「安装完成」横幅复用。
ADMIN_PASSWORD_SHOWN=""
ADMIN_USERNAME_SHOWN=""
FORCE_CONFIG=0
CONFIG_GENERATED=0
KEEP_DATA=0
ASSUME_YES=0
SKIP_TUNE=0
ACTION="install"
# 是否有任何参数被显式给出。没有任何参数且已安装时进菜单；只要给了参数就按
# 参数执行，自动化脚本因此完全不受菜单影响。
ARGS_GIVEN=0

while [[ $# -gt 0 ]]; do
  ARGS_GIVEN=1
  case "$1" in
    --transport)       TRANSPORT="${2:?--transport 需要一个值}"; shift 2 ;;
    --port)            PORT="${2:?--port 需要一个值}"; shift 2 ;;
    --listen)          LISTEN="${2:?--listen 需要一个值}"; shift 2 ;;
    --name)            LINE_NAME="${2:?--name 需要一个值}"; shift 2 ;;
    --admin-password)  ADMIN_PASSWORD="${2:?--admin-password 需要一个值}"; shift 2 ;;
    --admin-username)  ADMIN_USERNAME="${2:?--admin-username 需要一个值}"; shift 2 ;;
    --webui-listen)    WEBUI_LISTEN="${2:?--webui-listen 需要一个值}"; WEBUI_LISTEN_GIVEN=1; shift 2 ;;
    --webui-allow-remote) WEBUI_ALLOW_REMOTE=1; shift ;;
    --force-config)    FORCE_CONFIG=1; shift ;;
    --skip-tune)       SKIP_TUNE=1; shift ;;
    --uninstall)       ACTION="uninstall"; shift ;;
    --keep-data)       KEEP_DATA=1; shift ;;
    --yes|-y)          ASSUME_YES=1; shift ;;
    --reset-password)  ACTION="reset-password"; shift ;;
    --status)          ACTION="status"; shift ;;
    --menu)            ACTION="menu"; shift ;;
    -h|--help)         usage; exit 0 ;;
    *)                 die "未知参数：$1（使用 --help 查看用法）" ;;
  esac
done

# 监听地址不是回环就必须显式确认，与二进制侧同一条规则：两边判断不一致的话，
# 脚本会先接受一个地址、再让 init 报错，用户看到的是半途失败。
if [[ "${WEBUI_LISTEN}" != 127.0.0.1:* && "${WEBUI_LISTEN}" != localhost:* \
   && "${WEBUI_LISTEN}" != "[::1]:"* && "${WEBUI_ALLOW_REMOTE}" -ne 1 ]]; then
  die "--webui-listen ${WEBUI_LISTEN} 不是回环地址；把管理后台暴露到网络上需要同时加 --webui-allow-remote"
fi

# --port 只是 --listen 的简写，两者都给出时以 --listen 为准。
if [[ -z "${LISTEN}" && -n "${PORT}" ]]; then
  LISTEN="0.0.0.0:${PORT}"
fi

case "${ACTION}" in
  install)
    # 重跑（不带任何参数、且在终端里）时给菜单：装完之后最常见的动作是查看
    # 状态、取凭据、改密码，而不是重装。带参数时行为完全不变，所以
    # `curl … | bash -s -- --transport tls --port 8443` 这类用法不受影响。
    if [[ "${ARGS_GIVEN}" -eq 0 ]] && [[ -x "${BIN_PATH}" ]] && has_terminal; then
      do_menu
    else
      do_install
    fi
    ;;
  uninstall)      do_uninstall ;;
  reset-password) do_reset_password ;;
  status)         do_status ;;
  menu)           do_menu ;;
  *)              die "未知操作：${ACTION}" ;;
esac
