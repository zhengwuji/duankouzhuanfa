#!/usr/bin/env bash
# 让 PortTransit 网页控制台可以用「服务器IP:端口」直接打开。
#
# 只改配置里的控制台字段（webui.listen / webui.allowRemote，必要时
# webui.enabled），线路、PSK、控制台账号密码都不动；改前自动备份，
# 改完先让程序自己加载校验一遍，校验不过立刻回滚。
#
# 用法（在服务器上执行，任选其一）：
#   curl -fsSL https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/enable-console-remote.sh | sudo bash
#   sudo bash enable-console-remote.sh              # 已经下载到服务器上时
#   sudo bash enable-console-remote.sh --loopback   # 改回只允许本机
#   sudo PORT=9443 bash enable-console-remote.sh    # 换成别的端口（--loopback 同样适用）
#
# 环境变量：
#   PORT=8787                                 控制台端口
#   CONFIG_PATH=/etc/porttransit/config.json  配置文件
#   BIN_PATH=/usr/local/bin/porttransit       可执行文件
#   EDIT_TOOL=auto                            auto | python3 | sed（没有 python3 时用 sed）
#
# 说明：新版二进制自带同样的功能，升级后更推荐直接执行：
#   porttransit set-console --listen 0.0.0.0:8787 --allow-remote
# 本脚本做的是同一件事，供尚未升级的机器使用。

set -Eeuo pipefail
trap 'printf "\033[31m✘\033[0m 第 %s 行执行失败：%s\n" "${LINENO}" "${BASH_COMMAND}" >&2' ERR

info() { printf '\033[36m==>\033[0m %s\n' "$*" >&2; }
ok()   { printf '\033[32m✔\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[33m!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m✘\033[0m %s\n' "$*" >&2; exit 1; }

CONFIG_PATH="${CONFIG_PATH:-/etc/porttransit/config.json}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/porttransit}"
PORT="${PORT:-8787}"
EDIT_TOOL="${EDIT_TOOL:-auto}"
MODE="expose"

RAW_URL="https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/enable-console-remote.sh"
# 从文件运行就用文件本身来重复提示；`curl … | bash` 时 $0 是 "bash"、文件不存在，
# 这种情况下提示改用 curl 形式，免得打印出「sudo bash bash --loopback」这种东西。
SELF="${BASH_SOURCE[0]:-}"
[[ -n "${SELF}" && -r "${SELF}" ]] || SELF=""
self_cmd() {
  local extra="${1:-}"
  if [[ -n "${SELF}" ]]; then
    printf 'sudo bash %s%s\n' "${SELF}" "${extra:+ ${extra}}"
  else
    printf 'curl -fsSL %s | sudo bash -s --%s\n' "${RAW_URL}" "${extra:+ ${extra}}"
  fi
}

usage() {
  if [[ -n "${SELF}" ]]; then
    sed -n '2,22p' "${SELF}" | sed 's/^# \{0,1\}//'
  else
    printf '让 PortTransit 网页控制台可以用「服务器IP:端口」直接打开。\n'
    printf '用法：curl -fsSL %s | sudo bash -s -- [--loopback]\n' "${RAW_URL}"
    printf '详细说明：%s\n' "${RAW_URL}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --loopback) MODE="loopback"; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) die "未知参数：$1（可用：--loopback、--help）" ;;
  esac
done

[[ "$(id -u)" == "0" ]] || die "请用 root 执行：$(self_cmd)"
if [[ ! "${PORT}" =~ ^[0-9]+$ ]] || (( 10#${PORT} < 1 || 10#${PORT} > 65535 )); then
  die "PORT=${PORT} 不是有效端口（1-65535）"
fi
[[ -f "${CONFIG_PATH}" ]] || die "找不到配置文件 ${CONFIG_PATH}：先用一键脚本安装 PortTransit"

if [[ ! -x "${BIN_PATH}" ]]; then
  BIN_PATH="$(command -v porttransit || true)"
  [[ -n "${BIN_PATH}" ]] || die "找不到 porttransit 可执行文件（可加 BIN_PATH=/实际/路径 再试）"
fi

if [[ "${MODE}" == "expose" ]]; then
  LISTEN="0.0.0.0:${PORT}"
  ALLOW_REMOTE="true"
else
  LISTEN="127.0.0.1:${PORT}"
  ALLOW_REMOTE="false"
fi

# 老版本的 porttransit 可能没有 show-console 子命令；有的话就用它做体检，
# 没有就退化成 JSON 语法检查，免得把一台本来好好的机器“校验”回滚。
SHOW_CONSOLE_OK=0
if "${BIN_PATH}" show-console --config "${CONFIG_PATH}" >/dev/null 2>&1; then
  SHOW_CONSOLE_OK=1
fi

info "当前控制台"
"${BIN_PATH}" show-console --config "${CONFIG_PATH}" || warn "show-console 读取失败，先继续"

BACKUP="${CONFIG_PATH}.bak-$(date +%Y%m%d-%H%M%S)"
cp -a "${CONFIG_PATH}" "${BACKUP}"
ok "已备份配置：${BACKUP}"

edit_with_python3() {
  LISTEN="${LISTEN}" ALLOW_REMOTE="${ALLOW_REMOTE}" CONFIG_PATH="${CONFIG_PATH}" python3 - <<'PY'
import json, os, pathlib, sys

p = pathlib.Path(os.environ["CONFIG_PATH"])
try:
    cfg = json.loads(p.read_text())
except Exception as exc:
    print("无法解析 %s：%s" % (p, exc), file=sys.stderr)
    sys.exit(1)

webui = cfg.setdefault("webui", {})
if webui.get("enabled") is False:
    print("注意：webui.enabled 原为 false，已改成 true（否则控制台不会启动）", file=sys.stderr)
webui["enabled"] = True
webui["listen"] = os.environ["LISTEN"]
webui["allowRemote"] = os.environ["ALLOW_REMOTE"] == "true"

p.write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n")
PY
}

edit_with_sed() {
  local count
  count="$(grep -c -E "\"listen\"[[:space:]]*:[[:space:]]*\"[^\"]*:${PORT}\"" "${CONFIG_PATH}" || true)"
  if [[ "${count}" != "1" ]]; then
    warn "配置里有 ${count} 处监听 ${PORT} 端口，sed 模式分不清哪个是控制台；请改用 python3 或手动编辑"
    return 1
  fi
  sed -i -E "s|\"listen\"([[:space:]]*:[[:space:]]*)\"[^\"]*:${PORT}\"|\"listen\"\1\"${LISTEN}\"|" "${CONFIG_PATH}"
  if grep -q '"allowRemote"' "${CONFIG_PATH}"; then
    # 注意分隔符用 #：模式里有 (true|false) 这个分组，用 | 当分隔符会被 sed 当成第二段模式
    sed -i -E "s#\"allowRemote\"([[:space:]]*:[[:space:]]*)(true|false)#\"allowRemote\"\1${ALLOW_REMOTE}#" "${CONFIG_PATH}"
  elif [[ "${ALLOW_REMOTE}" == "true" ]]; then
    # 控制台这一段里 listen 后面还有别的字段（正常配置都是这样）才能安全插入：
    # 直接把整段「listen 行 + 逗号」后面接上新字段，逗号一个不多一个不少。
    if grep -q -E "\"listen\"[[:space:]]*:[[:space:]]*\"${LISTEN}\"," "${CONFIG_PATH}"; then
      sed -i -E "s|(\"listen\"[[:space:]]*:[[:space:]]*\"${LISTEN}\",)|\1\n        \"allowRemote\": true,|" "${CONFIG_PATH}"
    else
      warn "控制台监听地址是 webui 段里的最后一个字段，sed 模式不敢插新字段（怕把逗号写坏）；请改用 python3 或手动编辑"
      return 1
    fi
  fi
  grep -q -E "\"listen\"[[:space:]]*:[[:space:]]*\"${LISTEN}\"" "${CONFIG_PATH}"
}

info "把控制台监听地址改成 ${LISTEN}"
if ! case "${EDIT_TOOL}" in
  python3) edit_with_python3 ;;
  sed)     edit_with_sed ;;
  auto)
    if command -v python3 >/dev/null 2>&1; then
      edit_with_python3
    else
      warn "服务器上没有 python3，改用 sed"
      edit_with_sed
    fi ;;
  *) die "EDIT_TOOL=${EDIT_TOOL} 不支持（可用：auto、python3、sed）" ;;
esac; then
  cp -a "${BACKUP}" "${CONFIG_PATH}"
  die "改配置失败，已恢复备份 ${BACKUP}"
fi

# 校验一：JSON 语法（sed 路径尤其需要，改坏了要立刻发现）
if command -v python3 >/dev/null 2>&1; then
  if ! JSON_ERR="$(python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${CONFIG_PATH}" 2>&1)"; then
    cp -a "${BACKUP}" "${CONFIG_PATH}"
    printf '%s\n' "${JSON_ERR}" >&2
    die "改完的配置不是合法 JSON，已恢复备份 ${BACKUP}"
  fi
fi

# 校验二：用程序自己加载一遍：解析、校验、算控制台地址，等于一次体检。
if [[ "${SHOW_CONSOLE_OK}" == "1" ]]; then
  if ! LOADED="$("${BIN_PATH}" show-console --config "${CONFIG_PATH}" 2>&1)"; then
    cp -a "${BACKUP}" "${CONFIG_PATH}"
    printf '%s\n' "${LOADED}" >&2
    die "改完的配置没通过校验，已恢复备份 ${BACKUP}"
  fi
  ok "配置校验通过"
else
  warn "这台机器的 porttransit 没有 show-console 子命令，跳过深度校验（可看 systemctl status porttransit）"
fi

info "重启 porttransit"
if systemctl restart porttransit; then
  if systemctl is-active --quiet porttransit; then
    ok "服务已启动"
  else
    warn "服务没有处于 active 状态，日志如下："
    journalctl -u porttransit -n 30 --no-pager >&2 || true
  fi
else
  warn "重启失败，日志如下："
  journalctl -u porttransit -n 30 --no-pager >&2 || true
fi

if [[ "${MODE}" == "expose" ]]; then
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw allow "${PORT}/tcp" >/dev/null 2>&1 && ok "ufw 已放行 ${PORT}/tcp" || warn "ufw 放行失败，请手动执行：ufw allow ${PORT}/tcp"
  fi
  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -qi running; then
    if firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 && firewall-cmd --reload >/dev/null 2>&1; then
      ok "firewalld 已放行 ${PORT}/tcp"
    else
      warn "firewalld 放行失败，请手动执行：firewall-cmd --permanent --add-port=${PORT}/tcp && firewall-cmd --reload"
    fi
  fi
  if command -v iptables >/dev/null 2>&1 && iptables -S INPUT 2>/dev/null | grep -qE 'DROP|REJECT'; then
    warn "检测到 iptables 有 DROP/REJECT 规则；客户端连不上时请手动放行 ${PORT}/tcp"
  fi
fi

echo >&2
"${BIN_PATH}" show-console --config "${CONFIG_PATH}" >&2 || true
echo >&2

if [[ "${MODE}" == "expose" ]]; then
  ok "控制台已改成外网可访问（${LISTEN}）"
  cat >&2 <<EOF
   浏览器打开：http://<服务器公网IP>:${PORT}    账号：admin（密码沿用原配置）
   打不开先查两件事：云厂商安全组 / 防火墙有没有放行 ${PORT}/tcp；密码忘了就在服务器执行
   ${BIN_PATH} reset-password --config ${CONFIG_PATH}
   改回只允许本机：$(self_cmd --loopback)
   撤销这次修改：sudo cp -a ${BACKUP} ${CONFIG_PATH} && sudo systemctl restart porttransit
EOF
else
  ok "控制台已改回只允许本机（${LISTEN}）"
  cat >&2 <<EOF
   外部浏览器访问需要 SSH 隧道：
   ssh -N -L ${PORT}:127.0.0.1:${PORT} root@<服务器地址>
   然后打开 http://127.0.0.1:${PORT}
EOF
fi
