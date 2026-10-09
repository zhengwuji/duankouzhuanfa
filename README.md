# PortTransit

**端口转发 / 中转系统** — 用一个线路好的中转服务器，把线路差的服务器流量接管过去。

典型场景：直连美国服务器延迟高、丢包严重，但有一台上海中转机线路很好。
把流量先送到上海，再由上海转发到美国，整体体验会明显改善。PortTransit
负责的就是这条链路的两端：**中转服务端**（装在上海）和**客户端**（装在你本地）。

```
   你的电脑                上海中转机                    美国服务器
  ┌────────┐            ┌──────────┐                 ┌──────────┐
  │ 客户端 │ ──加密隧道─▶│ 服务端   │──────直连──────▶│ 目标服务 │
  └────────┘            └──────────┘                 └──────────┘
      │
      └─ 本地 SOCKS5 / HTTP 代理，或固定端口转发
```

---

## 目录

- [核心特性](#核心特性)
- [快速开始](#快速开始)
- [中转协议](#中转协议)
- [网页控制台](#网页控制台)
- [命令行](#命令行)
- [配置文件](#配置文件)
- [性能调优](#性能调优)
- [工作原理](#工作原理)
- [安全说明](#安全说明)
- [常见问题](#常见问题)
- [更新日志](#更新日志)

---

## 核心特性

| 能力 | 说明 |
|---|---|
| **多种加密协议** | TLS / REALITY / VLESS / VMess / Trojan / Shadowsocks-2022 / WebSocket / HTTPUpgrade / SOCKS5 / 直连 |
| **网页控制台** | 添加服务器、配置转发规则、查看线路健康、实时日志、一键改密码 |
| **远程部署** | 控制台里填 SSH 信息，自动给远程服务器装好服务端并回填凭据 |
| **一键脚本** | `install.sh` 负责安装、彻底卸载、重置管理员密码 |
| **内核调优** | 安装时自动开启 BBR 并调整缓冲区，跨国线路提速最明显的一项 |
| **本地代理** | 内置 SOCKS5 + HTTP 代理，可做分流（直连 / 走中转 / 拦截） |
| **固定端口转发** | 把本地端口钉到某个目标，适合游戏、SSH、数据库等固定场景 |
| **自动故障切换** | 同一分组的服务器健康探测 + 迟滞判断，坏了自动切，好了自动切回 |
| **协议伪装** | REALITY 借用真实网站的证书；Trojan 未认证流量直接转发到真实网站 |
| **单文件部署** | 整个程序编译成一个二进制，控制台前端也内嵌在里面 |

---

## 快速开始

### 一、在中转服务器上安装服务端

Debian / Ubuntu，root 权限：

```bash
curl -fsSL https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/install.sh | sudo bash -s -- --transport tls --port 8443
```

或者把脚本下载下来看一遍再执行：

```bash
wget https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/install.sh
sudo bash install.sh --transport reality --port 443
```

安装完成会打印**中转凭据**和**控制台初始密码**。密码只显示一次，请立刻保存。

其他操作：

```bash
sudo bash install.sh --status            # 查看运行状态
sudo bash install.sh --reset-password    # 重置控制台密码（随机生成）
sudo bash install.sh --reset-password --admin-password '你的新密码'
sudo bash install.sh --uninstall         # 彻底卸载（含配置与数据）
sudo bash install.sh --uninstall --keep-data   # 卸载但保留配置
sudo bash install.sh --uninstall --yes   # 卸载时不询问（脚本/自动化里必须加）
```

> `--uninstall` 会删掉配置与数据，所以默认要输入 `yes` 确认。非交互环境
> （CI、Ansible 等）请显式加 `--yes`，否则脚本会拒绝执行而不是默默删库。
> 脚本也会在**真正由 systemd 引导**的主机上才继续安装；WSL、Docker 这类
> 环境虽然带 `systemctl` 命令但没有可用的 dbus，会在改动系统之前就退出，
> 并提示改用 `porttransit run` 前台运行。

### 二、在本地电脑上运行客户端

```bash
# 1. 生成客户端配置
porttransit init --mode client --config ./client.json

# 2. 编辑 client.json，在 servers 里填入中转服务器信息
#    或者直接启动控制台，在网页里添加

# 3. 启动
porttransit run --config ./client.json
```

启动后打开控制台：<http://127.0.0.1:8787>

在 **中转服务器** 页面点「添加中转服务器」，填入第一步拿到的地址和凭据。
然后在 **远程部署** 页面可以直接通过 SSH 给新服务器安装服务端，装完自动回填。

### 三、使用

客户端默认在本地开两个代理端口：

| 端口 | 协议 | 用途 |
|---|---|---|
| `127.0.0.1:1080` | SOCKS5 | 浏览器插件、Telegram、大多数软件 |
| `127.0.0.1:8118` | HTTP | 系统代理、curl、git 等 |

测试：

```bash
curl --socks5 127.0.0.1:1080 https://ifconfig.me
curl --proxy  127.0.0.1:8118 https://ifconfig.me
```

固定端口转发在 **端口转发** 页面配置，例如把本地 `127.0.0.1:25565` 直接
转发到 `mc.example.com:25565`，走中转线路。

---

## 中转协议

控制台里选择协议时会标注**加密**或**明文**。

| 协议 | 加密 | 默认端口 | 适用场景 |
|---|---|---|---|
| `tls` | ✅ | 443 | **推荐默认**。真 TLS 1.3，可伪装浏览器指纹 |
| `reality` | ✅ | 443 | 借用真实网站证书，抗主动探测最强 |
| `vless` | ✅ | 443 | 开销最小，需跑在 TLS 之上 |
| `vmess` | ✅ | 443 | 兼容 v2ray 生态的旧客户端 |
| `trojan` | ✅ | 443 | 未认证流量转发到真实网站，伪装成 HTTPS |
| `shadowsocks` | ✅ | 8388 | Shadowsocks-2022，自带重放防护 |
| `websocket` | ❌ | 8080 | 能穿 CDN 和公司代理 |
| `httpupgrade` | ❌ | 80 | WebSocket 形状握手但不分帧，开销更低 |
| `http` | ❌ | 8080 | 标准 HTTP CONNECT 代理 |
| `socks5` | ❌ | 1080 | 标准 SOCKS5，便于串联 |
| `direct` | ❌ | 8080 | 只做转发不加密，**仅限内网或已有隧道** |

> **明文协议警告**：`websocket`、`httpupgrade`、`http`、`socks5`、`direct`
> 只保护不了内容。如果这一段链路要经过公网，请选带 ✅ 的协议，或者把这些
> 协议套在 SSH / WireGuard 之类已经加密的隧道里。

### 怎么选

- **不确定选什么** → `tls`
- **被墙得厉害、需要抗探测** → `reality`
- **要过 CDN** → `websocket`
- **要给现成的 SOCKS5 客户端用** → `socks5`

---

## 网页控制台

客户端独有（服务端不监听任何管理端口，少一个攻击面）。

| 页面 | 作用 |
|---|---|
| **总览** | 连接数、流量、运行时长、监听状态 |
| **中转服务器** | 增删改服务器，指定协议与参数，单条测试连通性 |
| **端口转发** | 本地端口 → 目标地址，绑定到指定服务器或分组 |
| **线路健康** | 每条线路的延迟、连续失败次数、最近错误 |
| **远程部署** | 通过 SSH 给服务器一键安装服务端 |
| **日志** | 按级别过滤的实时日志 |
| **设置** | 改管理员账号密码、直接编辑配置、查看可用协议 |

### 安全设计

- 默认只监听 `127.0.0.1`。要对外暴露必须显式打开 `allowRemote` **并且**
  设置密码，否则配置校验会直接拒绝启动。
- 会话是服务端持有的随机令牌，`HttpOnly` + `SameSite=Strict`。
- 改密码会**踢掉所有会话**。
- API 永远不回显密钥，返回 `__redacted__` 占位符；前端原样提交时后端会
  自动还原，所以"看一眼再保存"不会把密钥覆盖掉。

---

## 命令行

```
porttransit run              按配置运行（服务端 / 客户端 / 两者）
porttransit server           仅以中转服务端运行
porttransit client           仅以客户端运行
porttransit status           显示当前配置摘要

porttransit init             生成配置文件
porttransit install          安装为系统服务（需要 root）
porttransit uninstall        彻底卸载
porttransit reset-password   重置管理员密码
porttransit show-credentials 打印中转凭据

porttransit deploy           通过 SSH 远程安装服务端
porttransit version          版本信息
```

常用参数：

```bash
# 生成一个 REALITY 服务端配置
porttransit init --mode server --transport reality --listen 0.0.0.0:443

# 前台调试运行，日志打到终端
porttransit run --config ./config.json --log-level debug --log-file -

# 远程部署，装完直接写进客户端配置
porttransit deploy --host 1.2.3.4 --user root --transport tls \
  --port 8443 --add-to ./client.json
```

### 跨平台远程部署

客户端在 Windows、服务端在 Linux 时，`deploy` **不会**把 Windows 程序传到
Linux 上——它会先读取本机程序的文件头，发现不能在目标平台上运行就自动改用
同目录下的 Linux 构建：

```
本地程序是 windows/amd64，无法在 linux/amd64 上运行，正在查找匹配的构建…
上传服务端程序（本地程序为 windows/amd64，改用 D:\porttransit\porttransit-linux-amd64）…
```

所以要在一台 Windows 机器上给 Linux 服务器装中转，请把发行版压缩包里的
`porttransit-linux-amd64`（ARM 服务器用 `-arm64`）解压到**和 `porttransit.exe`
同一个目录**，然后直接执行 `deploy` 即可。

如果本机没有对应构建，也可以让服务器自己下载：

```bash
porttransit deploy --host 1.2.3.4 --user root \
  --download-url 'https://example.com/porttransit_{os}_{arch}.tar.gz'
```

`{os}` / `{arch}` 会按服务器实际平台替换。网页控制台的「远程部署」页也有
对应的「服务端下载地址」输入框。

---

## 配置文件

默认位置：

- Linux root：`/etc/porttransit/config.json`
- 普通用户：`~/.config/porttransit/config.json`
- Windows：`%APPDATA%\porttransit\config.json`

文件权限 `0600`，因为里面存着凭据。

### 服务端示例

```json
{
  "schemaVersion": 2,
  "mode": "server",
  "log": { "level": "info" },
  "webui": { "enabled": true, "listen": "127.0.0.1:8787" },
  "server": {
    "dataDir": "/var/lib/porttransit",
    "listeners": [
      {
        "name": "relay-tls",
        "transport": "tls",
        "listen": "0.0.0.0:8443",
        "enabled": true,
        "settings": {
          "psk": "base64:...",
          "certFile": "/etc/porttransit/certs/relay.crt",
          "keyFile": "/etc/porttransit/certs/relay.key"
        }
      }
    ],
    "forwards": [],
    "acl": { "blockPrivate": true },
    "limits": {
      "handshakeTimeout": "10s",
      "idleTimeout": "300s",
      "dialTimeout": "10s",
      "bufferSize": 32768
    }
  }
}
```

### 客户端示例

```json
{
  "schemaVersion": 2,
  "mode": "client",
  "webui": { "enabled": true, "listen": "127.0.0.1:8787" },
  "client": {
    "servers": [
      {
        "id": "srv-shanghai",
        "name": "上海中转",
        "address": "sh.example.com:8443",
        "transport": "tls",
        "enabled": true,
        "group": "primary",
        "latencyTag": "日本→上海→美国",
        "settings": { "psk": "base64:...", "insecure": true, "fingerprint": "random-no-alpn" }
      },
      {
        "id": "srv-backup",
        "name": "备用线路",
        "address": "hk.example.com:8443",
        "transport": "tls",
        "enabled": true,
        "group": "primary"
      }
    ],
    "tunnels": [
      {
        "name": "游戏加速",
        "enabled": true,
        "listen": "127.0.0.1:25565",
        "target": "mc.example.com:25565",
        "group": "primary",
        "balance": "least-latency"
      },
      {
        "name": "DNS 加速",
        "enabled": true,
        "listen": "127.0.0.1:5353",
        "network": "udp",
        "target": "1.1.1.1:53",
        "group": "primary"
      }
    ],
    "proxy": {
      "enabled": true,
      "socks5Listen": "127.0.0.1:1080",
      "httpListen": "127.0.0.1:8118",
      "group": "primary",
      "balance": "least-latency",
      "directRules": [".cn", "localhost"],
      "proxyRules": []
    },
    "health": {
      "enabled": true,
      "interval": "30s",
      "timeout": "5s",
      "failures": 3,
      "successes": 2,
      "autoFailover": true
    }
  }
}
```

### 分流规则

`directRules` / `proxyRules` / `blockRules` 支持三种写法：

| 写法 | 含义 | 例子 |
|---|---|---|
| `host:port` | 精确匹配 | `example.com:443` |
| `host` | 该主机任意端口 | `example.com` |
| `.suffix` | 域名后缀 | `.cn` |

### TLS 指纹档位

`tls` 协议的 `fingerprint` 设置（不填等于 `chrome`）：

| 取值 | 说明 |
|---|---|
| `chrome`（默认） | 复刻 Chrome 的 ClientHello |
| `firefox` / `safari` / `edge` / `ios` / `android` | 对应浏览器 |
| `golang` | Go 自带 TLS 栈的指纹 |
| `random` | 每次连接重新打乱扩展顺序，指纹不固定 |
| `random-no-alpn` | 同上，但不带 ALPN |

> `random` 两档是在**真实 Chrome 指纹**的基础上打乱扩展顺序实现的——这正是
> Chrome 106+ 自己做的事，所以既真实又每次都不同。它们**不会**像 uTLS 自带的
> 随机档位那样有约 15% 的握手失败率（那两档会声明 X25519MLKEM768 却不发对应
> 的 key share，服务端回 HelloRetryRequest 后 uTLS 无法应答）。

判定顺序是 **拦截 → 直连 → 中转**。`proxyRules` 非空时它是白名单，
没命中的走直连（而不是丢弃，否则用户会以为是断网）。

### UDP 转发

转发规则的 `network` 字段可取 `tcp`（默认）或 `udp`：

```json
{ "name": "DNS 加速", "listen": "127.0.0.1:5353", "network": "udp", "target": "1.1.1.1:53" }
```

UDP 与 TCP 是两条独立的路径，同一个端口号需要**两条规则**分别配置。
UDP 隧道按「本地源地址」维护独立的上游会话：同一个本地程序发出的所有
数据包复用一条中转连接，空闲 60 秒自动回收，因此不会为每个数据包做一次
握手。

注意：UDP 转发依赖中转协议本身能承载数据报。当前只有 `socks5` 传输实现了
UDP 关联命令，其余传输请使用 TCP，或改用本地 SOCKS5 代理。

---

## 性能调优

跨国线路的瓶颈通常不是加密算法，而是**丢包**。默认的 CUBIC 拥塞控制一遇到
丢包就把窗口砍半，BBR 不这么做——所以在有丢包的线路上差距非常明显。

`install.sh` 会在安装时自动完成调优，写入独立的
`/etc/sysctl.d/99-porttransit.conf`（不碰系统原有配置，卸载时一并删除）。

安装日志里会看到：

```
==> 内核网络调优
✔ 拥塞控制：bbr  队列规则：fq
```

### 手动运行 / 预览

```bash
sudo porttransit tune              # 应用并持久化
sudo porttransit tune --show       # 只打印将要写入的内容，不做修改
sudo porttransit tune --no-persist # 本次生效，不写文件
sudo porttransit tune --revert     # 删除持久化文件
sudo bash install.sh --skip-tune   # 安装时跳过调优
```

### 调了什么

| 参数 | 作用 |
|---|---|
| `tcp_congestion_control = bbr` | 丢包时不砍窗口，跨国线路最关键的一项 |
| `default_qdisc = fq` | BBR 依赖的队列规则 |
| `rmem_max` / `wmem_max` / `tcp_rmem` / `tcp_wmem` | 带宽延迟积大，默认缓冲区会限制单连接吞吐 |
| `somaxconn` / `tcp_max_syn_backlog` | 并发连接多，默认队列在突发时丢握手 |
| `ip_local_port_range` | 每条客户端连接对应一条出站连接，默认端口范围会耗尽 |
| `tcp_tw_reuse` | 复用 TIME_WAIT 的出站连接 |
| `tcp_slow_start_after_idle = 0` | 长连接空闲后不重置拥塞窗口 |
| `tcp_mtu_probing` | 路径丢 ICMP 时自动降 MSS，避免黑洞 |
| `tcp_fastopen = 3` | SYN 携带数据，省一个 RTT |
| `tcp_keepalive_*` | 更快回收空闲连接 |

### 环境不满足时

调优是**尽力而为**的，任何一项失败都不会影响安装：

- **容器 / WSL**：`/proc/sys` 只读或部分可写，脚本会逐项尝试并报告哪些没生效，
  而不是整体跳过。
- **内核不支持 BBR**（4.9 以下）：只调整缓冲区与连接数，并明确告知。
- **写入被静默丢弃**：脚本会**读回校验**，不会把没生效的参数报成成功。

想确认当前状态：

```bash
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc
cat /etc/sysctl.d/99-porttransit.conf
```

---

## 工作原理

### 中转链路

1. 客户端按配置选一条中转线路（分组内按策略挑选健康节点）
2. 建立加密隧道，把「要访问谁」告诉中转服务端
3. 服务端做目的地策略检查，然后连上真正的目标
4. 双向透传，按空闲超时和限速收尾

### 健康检查与故障切换

客户端周期性对每条线路做一次完整握手探测（不是只 ping 端口 ——
凭据过期、防火墙中途 reset、进程崩了但 socket 还在内核队列里，
这些只有跑完整握手才能发现）。

判断带**迟滞**：连续失败 `failures` 次才下线，连续成功 `successes`
次才恢复。否则线路抖动会让活动节点来回横跳，把正在跑的连接全打断。

### 协议伪装

- **REALITY**：借用真实网站的证书。探测者拿到的是那个网站的真证书，
  主动探测和被动流量分析都看不出这是代理。
- **Trojan**：密码不对的流量直接转发到真实网站，返回的页面和真网站一样。
- **TLS**：可以复刻 Chrome / Firefox / Safari / Edge / iOS / Android 的
  ClientHello 指纹。另外有两个「随机」档位（`random`、`random-no-alpn`）：
  它们在每次连接时重新打乱扩展顺序，因此同一个客户端每次握手的指纹都不
  一样，比固定档位更难被指纹库匹配。

---

## 安全说明

已经做了的：

- 中转服务端的目的地默认**禁止访问内网地址**（RFC1918、回环、链路本地、
  CGNAT、云厂商 metadata 端点 169.254.169.254），避免凭据泄露后被拿去
  扫内网。
- 域名解析后会**再查一次**解析结果，防 DNS rebinding。
- 简单传输的前导帧带 HMAC 和防重放；没有密钥的探测者什么都拿不到。
- Shadowsocks-2022 校验时间戳窗口，抓包重放无效。
- 控制台 API 不回显密钥。
- systemd 单元限制了能力集、只读挂载、禁止提权。

需要你自己注意的：

- **明文协议不要暴露在公网**（见上面的协议表）。
- **凭据要保管好**。中转服务端能访问的网段，拿到凭据的人也能访问。
- **控制台默认只监听本机**。要远程访问，请用 SSH 端口转发，而不是
  直接开放端口。
- 自签证书需要客户端 `insecure: true` 或指纹校验。如果中转机有域名，
  建议签一张真证书。

---

## 常见问题

**装好了但连不上？**

按顺序排查：

```bash
systemctl status porttransit          # 服务在跑吗
journalctl -u porttransit -n 50       # 日志说什么
ss -lntp | grep porttransit           # 端口在监听吗
sudo ufw status                       # 防火墙放行了吗
```

**控制台密码忘了？**

```bash
sudo bash install.sh --reset-password
# 或
sudo porttransit reset-password --config /etc/porttransit/config.json
```

**想换协议？**

编辑配置里的 `listeners[].transport` 与 `settings`，然后
`systemctl restart porttransit`。或者在控制台里重新生成一份配置。

**改了监听端口不生效？**

监听端口和本地绑定地址的改动**需要重启服务**，热重载只能改转发规则
之类的软配置。控制台在保存时会明确提示。

**延迟反而更高了？**

中转只在"中转机到目标"这段明显优于"你直连目标"时才有收益。
先用 **线路健康** 页面看看各段的实际延迟，确认中转机到目标确实更快。

**怎么彻底删干净？**

```bash
sudo bash install.sh --uninstall          # 会问一次，输入 yes
sudo bash install.sh --uninstall --yes    # 不询问（自动化）
```

会删掉服务、二进制、`/etc/porttransit`、`/var/lib/porttransit`、
`/var/log/porttransit`。加 `--keep-data` 可以保留配置。

---

## 开发

```bash
go build ./...
go vet ./...
go test ./...

# 构建带版本信息的二进制
go build -ldflags "-X porttransit/internal/version.Version=1.0.0 \
                   -X porttransit/internal/version.Commit=$(git rev-parse --short HEAD) \
                   -X porttransit/internal/version.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
         -o porttransit ./cmd/porttransit
```

### 目录结构

```
cmd/porttransit/          命令行入口
internal/
  app/                    把配置、日志、各子系统组装成一个进程
  client/                 客户端：隧道、本地代理、健康检查
  config/                 配置结构、校验、读写
  cryptox/                对称加密原语（AEAD / HKDF / UUID / 各类哈希）
  install/                安装、卸载、改密码、远程部署
  logx/                   日志（slog + 环形缓冲，供控制台读取）
  server/                 中转服务端：监听、ACL、UDP、统计
  sshdeploy/              SSH 远程安装
  transport/              传输层契约、前导帧、地址编码、自签证书
  transports/             各协议实现
  version/                版本信息
  webui/                  管理 API + 内嵌前端
scripts/install.sh        一键脚本
```

### 加一个新协议

1. 在 `internal/transports/<名字>/` 下新建包
2. 实现 `transport.Dialer` 和 `transport.Handler`
3. 在 `init()` 里 `transport.Register(...)`
4. 在 `internal/transports/transports.go` 里 blank import
5. 在 `internal/webui/server.go` 的 `transportEncrypted` 表里标注是否加密

---

## 更新日志

### v1.0.0 — 首个版本

**传输协议**

- 支持 10 种中转协议：`tls`、`reality`、`vless`、`vmess`、`trojan`、
  `shadowsocks`、`ws`、`httpupgrade`、`socks5`、`direct`
- TLS 支持浏览器指纹伪装（Chrome / Firefox / Safari / Edge / iOS / Android /
  Golang），另有两个随机档位 `random`、`random-no-alpn`——
  它们从**真实 Chrome 指纹**派生并在每次连接时打乱扩展顺序，
  既真实又每次都不同
- Shadowsocks 支持 2022 系列（`2022-blake3-aes-128-gcm` 等）与
  经典 AEAD-2017
- VLESS 支持 `xtls-rprx-vision` flow
- REALITY 使用伪造证书 + HMAC 认证，客户端校验失败即拒绝（不静默降级）

**服务端**

- 目的地 ACL：支持允许/拒绝列表、端口黑白名单、私网地址拦截、
  DNS rebinding 复查（解析后二次校验）
- 按客户端账号的独立策略
- 限速、并发上限、空闲超时
- UDP 转发（分帧 + 连接式 socket，避免放大攻击）
- 客户端握手限流（按 IP 令牌桶）
- 可选 PROXY protocol 输出、IPv4/IPv6 优先级策略

**客户端**

- 网页控制台：总览 / 中转服务器 / 端口转发 / 线路健康 / 远程部署 /
  日志 / 设置
- 本地 SOCKS5 + HTTP 代理，支持分流规则
- 线路健康探测与**迟滞**判断（连续失败才退休，连续成功才恢复），
  避免网络抖动导致线路反复横跳
- 固定端口转发（TCP 与 UDP）
- 多线路分组、多种负载均衡策略

**一键部署**

- `install.sh`：安装 / 彻底卸载 / 重置管理员密码 / 查看状态
- SSH 远程部署：在控制台填 SSH 信息即可给远程服务器装好服务端并回填凭据
- **跨平台部署**：Windows 客户端给 Linux 服务器装服务端时，会检测本机程序
  的文件头，发现平台不符就自动改用同目录下的 Linux 构建，
  不会把一个 Windows 程序传到 Linux 上
- 安装时自动进行**内核网络调优**（BBR + 缓冲区），并对每一项做读回校验

**安全**

- 配置文件中只保存 bcrypt 密码哈希，明文永不落盘
- 控制台默认只监听 `127.0.0.1`，远程访问必须显式开启并设置密码
- Session Cookie 使用 `HttpOnly` + `SameSite=Strict`，免 CSRF token
- 控制台 API 返回的配置会自动脱敏，密钥显示为 `__redacted__`
- systemd 单元启用 `NoNewPrivileges`、`ProtectSystem=strict`、
  `CapabilityBoundingSet` 等加固项
- 安装脚本会确认主机确实由 systemd 引导；容器 / WSL 会在改动系统前退出，
  而不是装到一半失败

---

## 许可

MIT
