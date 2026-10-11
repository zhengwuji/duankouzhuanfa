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
- [多路复用](#多路复用)
- [工作原理](#工作原理)
- [安全说明](#安全说明)
- [常见问题](#常见问题)
- [更新日志](#更新日志)

---

## 核心特性

| 能力 | 说明 |
|---|---|
| **多种加密协议** | TLS / REALITY / VLESS / VMess / Trojan / Shadowsocks-2022 / `ws`（WebSocket）/ HTTPUpgrade / HTTP CONNECT / SOCKS5 / 直连 |
| **网页控制台** | 添加服务器、配置转发规则、查看线路健康、实时日志、一键改密码 |
| **远程部署** | 控制台里填 SSH 信息，自动给远程服务器装好服务端并回填凭据 |
| **一键脚本** | `install.sh` 负责安装、彻底卸载、重置管理员密码 |
| **内核调优** | 安装时自动开启 BBR 并调整缓冲区，跨国线路提速最明显的一项 |
| **多路复用** | 一条连接承载多个转发流（yamux），短连接场景不再反复握手 |
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

安装完成会打印**控制台地址、用户名、密码**，以及**中转凭据**。密码只显示一次，请立刻保存：

```
╭──────────────────────────────────────────────╮
│            PortTransit 安装完成              │
╰──────────────────────────────────────────────╯

  网页控制台  http://203.0.113.10:8787
  管理员账号  admin
  管理员密码  xxxxxxxxxxxxxxxx

  服务状态  systemctl status porttransit
  ...
```

脚本的完整参数（`bash install.sh --help` 也是这份）：

```bash
--transport <名称>        中转协议，默认 tls（见「中转协议」表）
--port <端口>             中转监听端口，默认 8443
--listen <地址>           完整监听地址，例如 0.0.0.0:443（优先于 --port）
--name <名称>             线路名称，例如「上海中转」
--admin-password <密码>   控制台管理员密码（默认随机生成）
--admin-username <用户名> 控制台管理员用户名（默认 admin）
--webui-listen <地址>     控制台监听地址，默认 0.0.0.0:8787（公网可访问）；
                          已经装过时只改这一项，线路与凭据都不动
--webui-allow-remote      确认允许控制台监听非回环地址（默认已开启）
--force-config            覆盖已存在的配置（默认保留旧配置；会重新生成全部凭据）
--skip-tune               跳过内核网络调优，不写 /etc/sysctl.d
```

> **控制台默认监听 `0.0.0.0:8787`，公网可直接打开**，装完就能用打印出来的地址
> 登录。它只有密码一层防护，所以：登录失败会递增锁定（前 5 次不惩罚，之后每次
> 翻倍，最长 15 分钟），并且**请立刻改掉随机密码**。
> 只想本机访问就加 `--webui-listen 127.0.0.1:8787`，外部访问走 SSH 隧道：
> `ssh -N -L 8787:127.0.0.1:8787 root@你的服务器`，然后打开 `http://127.0.0.1:8787`。
> 服务器在 NAT 后面时，脚本会通过外部服务查出真实公网地址来拼这个链接。
>
> **已经装过、控制台却只有本机能打开**（旧版本的默认值是 `127.0.0.1:8787`）时
> 不用重装：重跑脚本加 `--webui-listen 0.0.0.0:8787`、在管理菜单里选 `8`、或者
> 直接 `sudo porttransit set-console --listen 0.0.0.0:8787 --allow-remote` 再
> `systemctl restart porttransit`，三种改法等价，只动监听地址。改完用
> `porttransit show-console` 确认，细节见「网页控制台 → 改成外网可访问」。

其他操作：

```bash
sudo bash install.sh --status            # 查看运行状态
sudo bash install.sh --reset-password    # 重置控制台密码（随机生成）
sudo bash install.sh --reset-password --admin-password '你的新密码'
sudo bash install.sh --uninstall         # 彻底卸载（含配置与数据）
sudo bash install.sh --uninstall --keep-data   # 卸载但保留配置
sudo bash install.sh --uninstall --yes   # 卸载时不询问，也不进菜单（自动化里必须加）
```

### 管理菜单

装完之后最常见的动作是查看状态、取凭据、改密码，而不是重装。**已经装过的机器
重新运行脚本会先进管理菜单**（带不带参数都一样，想在菜单里选 1 安装/更新就直接
选）：

```
╭──────────────────────────────────────────────╮
│           PortTransit 管理菜单               │
╰──────────────────────────────────────────────╯

  当前状态
    版本      PortTransit 1.1.0 (stable/88f2e34, linux-amd64, ...)
    服务      active / enabled
    中转线路  1 条
    控制台    http://203.0.113.10:8787

  1) 安装 / 更新服务端（保留现有配置）
  2) 查看运行状态
  3) 查看中转凭据（客户端连接用）
  4) 查看控制台地址与账号
  5) 重置控制台密码
  6) 重启服务
  7) 彻底卸载
  8) 控制台访问地址（外网 / 仅本机）
  0) 退出
```

也可以显式打开：`sudo bash install.sh --menu`。

> **已经装过的机器 + 终端里运行，就一定会先进菜单**（带不带参数都一样），这样
> 「运行安装命令」永远是从菜单里选一次，而不是靠记参数。要在终端里跳过菜单、
> 直接按参数执行，加 `--yes`：`curl … | bash -s -- --yes --transport tls --port 8443`。
> 没有终端（CI、cron、重定向）时不会进菜单 —— 卡在菜单上等于坏掉。
>
> 菜单的输入一律读 `/dev/tty` 而不是 stdin。因为文档里的主要用法是
> `curl … | bash`，那时 **stdin 就是脚本自身** —— 从 stdin 读会把后面的
> 脚本内容当成回答，卸载确认会形同虚设。

> 重装或改协议时注意 `--force-config` 的默认行为：**不带它就会保留已有配置**，
> 所以只改 `--transport` 而不加 `--force-config` 不会生效，看起来像参数没被读到。
> 唯一的例外是 `--webui-listen`：它只改控制台监听地址，**会在现有配置上直接生效**，
> 因为「把只有本机能打开的控制台改成外网可访问」不该逼用户去冒重新生成凭据的险。
> 反过来，什么都不给时它也不会去动别人特意设成仅本机的控制台。

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

`init` 会把生成的**管理员用户名（默认 `admin`）和密码**打在终端上，请先记下来。
Windows 上不写 `--config` 时的默认位置是 `%APPDATA%\porttransit\config.json`，
Linux 普通用户是 `~/.config/porttransit/config.json`（见「配置文件」）。

启动后打开控制台：<http://127.0.0.1:8787>，**先用上面那组用户名密码登录**——
控制台是一个需要登录的管理界面，没登录时看到的只有登录表单。密码只保存哈希，
`init` 之后找不回来；忘了就用 `porttransit reset-password` 或
`sudo bash install.sh --reset-password` 重新生成。

#### 1. 登录控制台，填入中转凭据

登录后在 **中转服务器** 页面点「添加中转服务器」。表单字段是
名称 / 服务器地址 / 协议 / 分组 / 线路标记 / 客户端 ID / 协议参数 (JSON) / 启用。

关键的一点：安装脚本打印的 `psk`、`uuid`、`password`、`publicKey` 这些值
**要作为 JSON 对象填进「协议参数」框**，不是一行一个字段。例如 `tls`：

```json
{ "psk": "base64:...", "insecure": true }
```

`reality`：

```json
{ "psk": "...", "publicKey": "...", "shortId": "...", "serverName": "www.bing.com" }
```

这些值从哪里来：

- 安装脚本在装完时打印过一遍。
- 之后在中转机上随时可以重新取回：`porttransit show-credentials`，输出是
  `key=value` 一行一项（REALITY 的 `publicKey` 由服务端保存的私钥现算出来，
  所以安装时没抄下来也拿得回）。
- 服务端自己的控制台（同一个 `127.0.0.1:8787`）也能生成这些值。

`insecure: true` 只是让自签证书不被拒绝；如果能拿到证书指纹，请改用
`certFingerprint`（见「证书指纹固定」）。

#### 2. 新建转发规则

**端口转发** 页面点「+ 新建转发」，字段是：本地监听地址 / 目标地址 /
指定服务器 / 分组 / 传输类型（TCP | UDP）/ 负载策略。

例如把本地 `127.0.0.1:25565` 直接转发到 `mc.example.com:25565`，走中转线路。
**新增或改动监听端口后需要重启客户端才会真正绑定**，控制台保存时会提示这一点；
只改目标地址之类的软配置才热生效。

负载策略可选 `first`（默认，按配置顺序）/ `round-robin` / `random` /
`least-latency`（延迟最低）。

### 三、使用

#### 本地代理

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

浏览器一般用 SwitchyOmega 这类扩展指向 `127.0.0.1:1080`（SOCKS5）；命令行
工具则可以直接给环境变量：

```bash
HTTPS_PROXY=http://127.0.0.1:8118 curl https://ifconfig.me
```

> **本地代理默认没有认证**，并且默认只绑定回环地址。这是刻意的——它靠
> 「只有本机能连」来防护，而不是靠密码。所以**不要**把 `socks5Listen` /
> `httpListen` 改成 `0.0.0.0`：那等于把你自己的出口代理开放给整个网络。
> 真要对外暴露，配置校验会强制你同时设置代理密码，但仍应优先考虑别这么做。

固定端口转发同样在 **端口转发** 页面配置。

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
| `ws` | ❌ | 8080 | WebSocket，能穿 CDN 和公司代理 |
| `httpupgrade` | ❌ | 80 | WebSocket 形状握手但不分帧，开销更低 |
| `http` | ❌ | 8080 | 标准 HTTP CONNECT 代理 |
| `socks5` | ❌ | 1080 | 标准 SOCKS5，便于串联 |
| `direct` | ❌ | 8080 | 只做转发不加密，**仅限内网或已有隧道** |

> **明文协议警告**：`ws`、`httpupgrade`、`http`、`socks5`、`direct`
> 只保护不了内容。如果这一段链路要经过公网，请选带 ✅ 的协议，或者把这些
> 协议套在 SSH / WireGuard 之类已经加密的隧道里。

### 怎么选

- **不确定选什么** → `tls`
- **被墙得厉害、需要抗探测** → `reality`
- **要过 CDN** → `ws`
- **要给现成的 SOCKS5 客户端用** → `socks5`

---

## 网页控制台

服务端和客户端都带控制台：`config.Default()` 对两种模式都开启它，默认监听
`127.0.0.1:8787`（仅本机，默认需要登录）。一键脚本安装的服务端默认改成
`0.0.0.0:8787`，详见下面「安全设计」。

| 页面 | 作用 |
|---|---|
| **总览** | 连接数、流量、运行时长、监听状态 |
| **中转服务器** | 增删改服务器，指定协议与参数，单条测试连通性 |
| **端口转发** | 本地端口 → 目标地址，绑定到指定服务器或分组 |
| **线路健康** | 每条线路的延迟、连续失败次数、最近错误 |
| **远程部署** | 通过 SSH 给服务器一键安装服务端 |
| **日志** | 按级别过滤的实时日志 |
| **设置** | 改管理员账号密码、直接编辑配置、查看可用协议 |

控制台自身由 `http://127.0.0.1:8787` 提供，它的 JSON API 挂在 `/api/v1/` 下
（例如 `/api/v1/config`、`/api/v1/tunnels`、`/api/v1/status`）。除
`/api/v1/login`、`/api/v1/logout` 和 `/api/v1/session` 之外，所有端点都要求
一个已登录的会话；`/api/v1/session` 本身就是「我现在登录了吗」的探针，
未登录时返回未授权而不是数据。

命令行也能查看控制台信息，不用去翻配置文件：

```bash
porttransit show-console        # 地址、用户名、是否启用
porttransit show-credentials    # 中转凭据（客户端连接用）
porttransit reset-password      # 换一个密码
porttransit set-console         # 改监听地址（外网 / 仅本机）
```

### 改成外网可访问（或改回仅本机）

已经装好的机器不用重装，控制台监听地址可以单独改，改完就是
`服务器IP:端口` 直接打开：

```bash
# 一键脚本（等价于安装时的 --webui-listen，只动监听地址）
sudo bash install.sh --webui-listen 0.0.0.0:8787    # 外网可访问
sudo bash install.sh --webui-listen 127.0.0.1:8787  # 改回仅本机
sudo bash install.sh --menu                         # 或者在菜单里选 8

# 或者直接对二进制说
sudo porttransit set-console --listen 0.0.0.0:8787 --allow-remote
sudo systemctl restart porttransit
porttransit show-console                            # 确认新地址
```

二进制还没有 `set-console`（v1.1.1 及更早）时用仓库里这个过渡脚本，做的事完全
一样，但自带备份、改完的加载校验和失败回滚：

```bash
curl -fsSL https://raw.githubusercontent.com/zhengwuji/duankouzhuanfa/main/scripts/enable-console-remote.sh | sudo bash
# 换端口：sudo PORT=9443 bash enable-console-remote.sh
# 改回仅本机：sudo bash enable-console-remote.sh --loopback
```

以上几种做法都只改配置文件里的 `webui.listen` 与 `webui.allowRemote`：**线路、管理员
密码、客户端凭据全都不动**（想改协议/端口请用 `--force-config`，那才是重生成
全部凭据的那条路）。几个行为细节：

- 非回环地址必须显式带确认位（二进制的 `--allow-remote`、脚本的
  `--webui-allow-remote`），否则会拒绝 —— 防止手滑把后台挂到公网上。
- 脚本还会顺手把控制台端口加进防火墙；只用 `set-console` 的话记得自己放行。
- 控制台还没有密码时不允许暴露（会被配置校验拒绝），先跑
  `porttransit reset-password`。
- 改完必须重启服务才生效；`set-console` 和脚本都会把这条命令打出来。

### 安全设计

- 默认监听 `127.0.0.1`（`porttransit init` 的默认值）。要对外暴露必须显式
  打开 `allowRemote` **并且**设置密码，否则配置校验会直接拒绝启动。
  **一键脚本刻意把默认值改成 `0.0.0.0:8787`**，因为装完就想直接打开控制台；
  它会在结果横幅里明确警告并把改回本机的方法打出来。
  旧版本装好的机器（控制台还是 `127.0.0.1:8787`）用
  `set-console` / `install.sh --webui-listen` / 菜单 `8` 切换，不用重装。
- 登录失败按来源地址递增锁定：前 5 次不惩罚（密码管理器也会打错），之后
  每次翻倍，最长 15 分钟。计数在成功登录后清零，15 分钟无失败也会过期。
  **按来源隔离**，所以一个攻击者无法把运维锁在外面。
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
porttransit show-console     打印控制台地址与用户名
porttransit set-console      修改控制台监听地址（外网 / 仅本机）
porttransit show-credentials 打印中转凭据

porttransit tune             应用内核网络调优（BBR 等）
porttransit fingerprint      计算中转服务端证书的 SHA-256 指纹

porttransit deploy           通过 SSH 远程安装服务端
porttransit version          版本信息
porttransit help             显示命令帮助
```

`show-credentials` 按 `key=value` 一行一项打印客户端连接所需的全部字段——
包括 REALITY 的 `publicKey`（由服务端保存的私钥现算出来）、`shortId` 和
`serverName`，所以凭据在安装时打印过一次之后仍然可以随时取回。

`tune` 的用法见下面的「性能调优」，`fingerprint` 的用法见「证书指纹固定」。

常用参数：

```bash
# 生成一个 REALITY 服务端配置
porttransit init --mode server --transport reality --listen 0.0.0.0:443

# 前台调试运行，日志打到终端
porttransit run --config ./config.json --log-level debug --log-file -

# 远程部署，装完直接写进客户端配置
porttransit deploy --host 1.2.3.4 --user root --transport tls \
  --port 8443 --add-to ./client.json

# 让控制台可以用 服务器IP:8787 直接打开（只改监听地址，凭据不动）
porttransit set-console --listen 0.0.0.0:8787 --allow-remote
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

### 在已有线路的服务器上再部署一条

`deploy` 是**追加**线路，不会动服务器上已有的其它线路。往一台已经跑着
relay 的服务器上再部署第二条，两条都会保留：

```bash
# 第一次：装 tls 线路到 8443
porttransit deploy --host 1.2.3.4 --transport tls --port 8443 --name relay-a

# 第二次：同一台服务器再加一条 reality 线路到 9443
porttransit deploy --host 1.2.3.4 --transport reality --port 9443 --name relay-b
# 服务器上现在有 2 条线路，relay-a 不受影响
```

几点行为说明：

- **同名即更新**：用同一个 `--name` 重跑，是修复那一条线路，而不是留下两条
  抢同一个端口的重复项。
- **端口被别的程序占用会直接拒绝**：所有线路在同一个进程里，一条线路绑不上
  端口会让整个服务起不来，连带把已经正常的线路一起弄挂。所以部署前会先检查
  端口，被其它程序占用时就停下并说明，不改动配置。
- **失败会回滚**：新配置启动失败或端口没监听时，会自动恢复部署前的配置并重启，
  不会把一台本来正常的服务器留在一个起不来的配置上。
- **管理员密码不会被改动**：追加线路不会重新生成控制台密码（重新生成会把你
  锁在控制台外面，而那个新密码根本不会显示出来）。要改密码用
  `porttransit reset-password` 或安装脚本的 `--reset-password`。
- **端口没监听 = 部署失败**：以前这里只是一条警告，所以会出现「提示部署成功、
  实际端口没开」的情况；现在会明确报失败并打印服务日志。

用 `--force` 覆盖、或者想手工在服务器上追加线路时，可以用：

```bash
porttransit init --config /etc/porttransit/config.json --add-listener \
  --transport vless --listen 0.0.0.0:10443 --name relay-c

# 只看某一条线路的凭据（默认只输出第一条已启用的）
porttransit show-credentials --config /etc/porttransit/config.json --name relay-c
```

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
          "mux": true,
          "certFile": "/etc/porttransit/certs/relay.crt",
          "keyFile": "/etc/porttransit/certs/relay.key"
        }
      }
    ],
    "forwards": [],
    "clients": [
      {
        "id": "laptop-01",
        "name": "家里的笔记本",
        "enabled": true,
        "credentials": {
          "tls": "base64:...",
          "reality": "..."
        },
        "allowedTargets": ["example.com:443"],
        "deniedTargets": ["169.254.169.254:80"],
        "maxConnections": 64,
        "rateLimitKBps": 2048,
        "quotaBytes": 107374182400,
        "expiresAt": "2027-01-01T00:00:00Z",
        "note": "按季度续期"
      }
    ],
    "acl": { "blockPrivate": true },
    "limits": {
      "handshakeTimeout": "10s",
      "idleTimeout": "300s",
      "dialTimeout": "10s",
      "bufferSize": 32768
    },
    "resolver": {
      "servers": ["1.1.1.1:53", "8.8.8.8:53"],
      "protocol": "udp",
      "timeout": "5s",
      "strategy": "prefer_ipv4"
    },
    "masking": {
      "mode": "none",
      "fallbackAddr": "www.bing.com:443",
      "fallbackServerName": "www.bing.com",
      "fallbackHTTPHost": "www.bing.com",
      "sniff": false
    }
  }
}
```

`server.clients`（账号策略）的字段：

| 字段 | 说明 |
|---|---|
| `id` | 客户端在 `clientId` 里上报的标识，也是策略的键 |
| `name` / `note` | 给人看的标签 |
| `enabled` | 关掉即停用该账号，不用删配置 |
| `credentials` | **按传输名做键**的子映射，一个账号可以同时持有多种协议的密钥 |
| `allowedTargets` / `deniedTargets` | 在全局 ACL 之上再收窄；拒绝优先于允许 |
| `maxConnections` | 并发上限，`0` 为不限 |
| `rateLimitKBps` | 限速（KB/s），`0` 为不限 |
| `quotaBytes` | 累计流量上限，`0` 为不限；用量持久化在 `dataDir/quota.json` |
| `expiresAt` | 到期时间（RFC3339）；不填表示永不过期 |

一旦配置了**任意一个**账号，策略就分成两种情形：

- 在能携带 `clientId` 的传输上（前导帧类：`direct` / `tls` / `ws` /
  `httpupgrade` / `reality`），未知或不存在的 `clientId` 会被**直接拒绝**。
  否则任何人换个 id 就能绕过按客户端的策略，账号功能形同虚设。
- 在自带共享密钥的传输上（`vless` / `trojan` / `shadowsocks` / `socks5` /
  `http`），认证靠的是协议头里的密钥本身，客户端无法自选身份。这类连接
  只由它自己的密钥管辖：匹配到账号就套用该账号的限额，匹配不到就按全局策略
  放行——严格拒绝会把「刚加了一个 id 不巧等于密钥的账号」变成全体断线。

`server.resolver` 覆盖中转机侧的目标解析：`servers`（DNS 地址列表）、
`protocol`（`udp` / `tcp` / `tcp-tls` / `https`）、`timeout`、`strategy`
（`prefer_ipv4` / `prefer_ipv6`）。

`server.masking` 决定未认证的探测者看到什么：`mode`
（`none` / `tls-fallback` / `http-fallback`）、`fallbackAddr`、
`fallbackServerName`、`fallbackHTTPHost`、`certFile` / `keyFile`、`sniff`。
它**只对 `trojan` / `http` / `httpupgrade` / `ws` 生效**——这四个协议有地方
可以把未认证流量转出去。配在其他协议上会打一条警告而不是静默失效，否则
运维会以为探测已经处理好了。

listener 与 forward 上还有几个容易漏的开关：`listener.tcpFastOpen`（需要在
bind 之前设置才有效，非 Linux 平台会明确告知已忽略）、`listener.mptcp`、
`listener.proxyProtocol`（接受入站 PROXY protocol v1/v2，让中转机在负载均衡
后面也能看到真实客户端地址），以及 `forward.proxyProtocolOut`（出站时加 v1
头，让目标看到原始客户端地址）。

转发规则里的 `balance` 可选 `first` / `round-robin` / `random` /
`least-latency` / `least-conn`；客户端隧道和本地代理的 `balance` 少一个
`least-conn`（它们选的是中转线路，不是目标主机）。

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
        "clientId": "laptop-01",
        "enabled": true,
        "group": "primary",
        "latencyTag": "日本→上海→美国",
        "settings": { "psk": "base64:...", "mux": true, "certFingerprint": "AA:BB:CC:...", "fingerprint": "random-no-alpn" }
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
| `random`（别名 `randomized`） | 每次连接重新打乱扩展顺序，指纹不固定 |
| `random-no-alpn` | 同上，但不带 ALPN |
| `none` | 不使用 uTLS，走标准库 `crypto/tls` 握手 |

> `random` 两档是在**真实 Chrome 指纹**的基础上打乱扩展顺序实现的——这正是
> Chrome 106+ 自己做的事，所以既真实又每次都不同。它们**不会**像 uTLS 自带的
> 随机档位那样有约 15% 的握手失败率（那两档会声明 X25519MLKEM768 却不发对应
> 的 key share，服务端回 HelloRetryRequest 后 uTLS 无法应答）。

### 证书指纹固定（certFingerprint）

`tls` / `vless` / `vmess` / `trojan` 四个协议都支持客户端设置
`certFingerprint`，用来固定中转服务端证书的 SHA-256 指纹：

```json
"settings": { "psk": "base64:...", "certFingerprint": "AA:BB:CC:..." }
```

不填就是原来的行为，不影响已有配置。

**自签证书请用 `certFingerprint`，不要用 `insecure: true`。**

`insecure: true` 是真的**完全不校验证书**：任何一台中间人都能拿自己的证书
冒充你的中转机，客户端不会有任何察觉。而 `certFingerprint` 会在每次连接时
比对中转服务端出示的证书指纹，不一致就直接断开，中间人换不了证书。

指纹从哪里来：

```bash
# 在中转机上，直接读证书文件
porttransit fingerprint --cert /etc/porttransit/certs/relay.crt

# 在客户端上，直接从运行中的中转服务端读取
porttransit fingerprint --server relay.example.com:8443
```

服务端启动后的日志里也会打一次自己的指纹，方便直接抄给客户端。

输入格式很宽松：大小写随意，冒号、短横线、空格都可以带也可以不带，
`AA:BB:CC`、`aabbcc`、`aa-bb-cc` 三者等价。但如果长度不对或者含有非十六进制
字符，客户端会**直接报错**而不是当作「没配置指纹」继续连接——打错一个字符
反而变成不校验，是这里最不能接受的失败方式。

同时配了 `certFingerprint` 和 `insecure: true` 时，**以 `certFingerprint`
为准**。指纹固定比「接受一切」强得多，如果因为 `insecure` 而把它跳过，配了
指纹的人会以为自己被固定住了，实际上什么都没校验。

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

UDP 转发依赖中转协议本身能承载数据报：

- `direct` / `tls` / `ws` / `httpupgrade` / `reality` 通过**前导帧**承载
  UDP——和中继 TCP 走的是同一条 `PreambleServerHandshake` 路径，中转机只看
  前导帧里的命令字节来决定开 TCP 还是 UDP 关联，所以这些协议在实现上都支持。
- `vless` / `vmess` / `trojan` / `socks5` 在**自己的协议头**里实现 UDP 命令，
  同样支持。
- `shadowsocks` 和 `http`（HTTP CONNECT）不支持 UDP：这两个实现的 relay 端
  都只构造 `CmdConnectTCP`——Shadowsocks 的请求格式里没有 UDP 关联这一说，
  而 HTTP CONNECT 本身表达的也只是一个 TCP 隧道。

不过「实现上支持」不等于「已经替你验证过」：自动化覆盖到的是 `socks5` 与
`direct`，其余组合请自己在你的线路和客户端版本上先跑一遍
`curl --socks5 127.0.0.1:1080` 之类的实测，再投入生产。

### 浏览器代理的 UDP（DNS 与 QUIC）

上面的固定端口转发只能钉死一个目标。如果希望**浏览器**通过代理发 DNS 查询
或走 QUIC/HTTP3，需要本地 SOCKS5 代理支持 `UDP ASSOCIATE`：

```json
"proxy": { "enabled": true, "udp": true, "socks5Listen": "127.0.0.1:1080" }
```

或者直接在控制台的设置页打开。不开启时，SOCKS5 会对 UDP ASSOCIATE 回
`0x07`，浏览器只能退回 TCP 并用系统解析器——**那会泄漏你正在访问的域名**，
所以需要隐藏访问目标时应当开启。

开启后：

- 每个客户端 TCP 控制连接对应一个 UDP 关联，控制连接断开即回收。
- 同一个目标地址复用一条中转流，不会为每个数据包握手。
- 关联绑定到控制连接的对端地址，其他本机进程无法注入或窃听。
- 分片（`FRAG != 0`）的数据包会被丢弃：重组是放大攻击面，而浏览器不使用它。
- 目的地址仍然受分流规则约束（直连 / 走中转 / 拦截）。

---

## 性能调优

跨国线路的瓶颈通常不是加密算法，而是**丢包**。默认的 CUBIC 拥塞控制一遇到
丢包就把窗口砍半，BBR 不这么做——所以在有丢包的线路上差距非常明显。

`install.sh` 会在安装时自动完成调优，写入独立的
`/etc/sysctl.d/99-porttransit.conf`（不碰系统原有配置，卸载时一并删除）。

安装日志里会看到：

```
==> 内核网络调优
✔ 拥塞控制 bbr，队列规则 fq
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
- **BBR 未生效**（内核 4.9 以下，或 `tcp_bbr` 模块缺失）：只调整缓冲区与连接数，
  并明确告知。脚本会先尝试 `modprobe tcp_bbr`，再直接写入 `tcp_congestion_control`
  并以**读回结果**判断是否生效——内核会在写入时自动加载算法模块，所以
  `tcp_available_congestion_control` 里没有 bbr 并不代表不能用。
- **写入被静默丢弃**：脚本会**读回校验**，不会把没生效的参数报成成功。

想确认当前状态：

```bash
sysctl net.ipv4.tcp_congestion_control net.core.default_qdisc
cat /etc/sysctl.d/99-porttransit.conf
```

---

## 多路复用

上面两项优化的是**单个连接**能跑多快。这一项优化的是**建连接**要花多久。

浏览器打开一个网页会开几十条短连接，而每条连接都要和跨国中转机重新做一次完整握手
（TCP 三次握手 + TLS/REALITY 握手，通常 2～4 个 RTT）。在 200ms 的线路上，这就是每条
连接白等半秒左右——握手时间比传输本身还长。

开启多路复用后，客户端和中转机之间**只保持一条连接**，所有转发流作为这条连接里的
「子流」传输。第二条之后的连接**不再握手**，而且所有子流共用同一个拥塞窗口，在有丢包
的线路上比几十个窗口互相竞争表现更好。

会话层由 [hashicorp/yamux](https://github.com/hashicorp/yamux) 提供。子流支持半关闭
（一端写完后发 FIN，另一端仍可继续回包），所以「请求发完就关闭写侧、再等服务端回复」
这种协议形态不会被截断。

### 怎么开启

两端都要开（中转机的 listener 和客户端的服务器条目各写一次）：

```json
// 服务端 listener
"settings": { "psk": "base64:...", "mux": true }

// 客户端服务器条目
"settings": { "psk": "base64:...", "mux": true }
```

或者在网页控制台的「中转服务端 / 服务器」表单里，往协议参数 JSON 里加上
`"mux": true`。

> **默认关闭。** 不写这个键的行为和以前完全一样（一条转发流一条连接），
> 已有部署升级后不受影响。

### 支持范围

只有**通过前导帧携带目标地址**的协议能承载多路复用：

| 协议 | 支持 |
|---|---|
| `direct`、`tls`、`reality`、`ws`、`httpupgrade` | ✅ |
| `vless`、`vmess`、`trojan`、`shadowsocks`、`socks5` | ❌ |

原因是后者的目标地址写在协议自己的头部里，没有「连接级命令」这个位置可以表达
「请把这条连接当成会话」。在控制台或配置里给这些协议开了 `mux` 也不会坏——
客户端会**自动退回**成一条连接一条流，并在日志里说明一次。

### 可调参数

| 键 | 默认 | 说明 |
|---|---|---|
| `mux` | `false` | 总开关 |
| `muxMaxStreams` | `256` | 单会话并发子流上限。yamux 本身没有这个限制，由两端各自强制执行 |
| `muxMaxSessions` | `4` | 客户端对同一中转最多开几个会话，超过后退回独立连接 |
| `muxIdleTimeout` | 客户端 `60s` / 服务端 `300s` | 空闲会话回收时间，`0` 表示不回收 |
| `muxKeepAliveInterval` | `30s` | 保活探测间隔 |
| `muxKeepAliveDisabled` | `false` | 关掉保活探测 |
| `muxMaxWindowSize` | `256*1024` | 单条子流的接收窗口。**yamux 要求不小于 256 KiB**，写小了会被抬到 256 KiB |
| `muxAcceptBacklog` | `256` | 等待被接受的子流上限 |
| `muxStreamOpenTimeout` | `75s` | 子流打开后等待对方确认的最长时间，`0` 表示不限 |
| `muxStreamCloseTimeout` | `5m` | 半关闭后等待对方 FIN 的最长时间，超时则强制关闭，`0` 表示不限 |
| `muxConnectionWriteTimeout` | `10s` | 底层连接写入超时，超时即认为连接已死 |

两端参数不一致**不会挂住**：客户端收到拒绝会立刻退回独立连接，表现为「慢一点」而不是「连不上」。

### 安全说明

多路复用**不会**绕过任何策略。每条子流都带自己的前导帧，因此中转机会对每条子流
单独做 ACL 检查、账号并发/配额/限速检查、转发规则匹配——和中继一整条连接时完全一样。
中转机侧还会为整个 listener 共享一个防重放窗口（而不是每个子流一个），
否则兄弟子流之间可以互相重放。

---

## 工作原理

### 中转链路

1. 客户端按配置选一条中转线路（分组内按策略挑选健康节点）
2. 建立加密隧道，把「要访问谁」告诉中转服务端
3. 服务端做目的地策略检查，然后连上真正的目标
4. 双向透传，按空闲超时和限速收尾

### 负载均衡策略

客户端（隧道与本地代理）在分组内按 `balance` 挑线路：

| 取值 | 行为 |
|---|---|
| `first`（默认） | 保持配置顺序，列表里的第一个可用节点优先——先主后备的直觉写法 |
| `round-robin` | 按秒轮转，同一秒内的连接落在同一个节点，突发流量不会扇出到所有上游 |
| `random` | 随机打乱 |
| `least-latency` | 延迟最低优先；从未测过的节点排在最后，所以第一条连接会先赌已知快的 |

服务端的转发规则（`server.forwards[].balance`，用在 `target` 写了多个逗号
分隔主机时）另外多一个 `least-conn`，按当前连接数最少挑。写错的值会被配置
校验拒绝，而不是静默退回默认。

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
- `tls` / `vless` / `vmess` / `trojan` 支持用 `certFingerprint` 固定中转服务端
  证书的 SHA-256 指纹，中间人换证书会被直接拒绝；配置了指纹时它优先于
  `insecure`。指纹格式写错会报错而不是静默跳过校验。
- 控制台 API 不回显密钥。
- systemd 单元限制了能力集、只读挂载、禁止提权。
- 仓库自带凭据扫描：`make lint` 会检查是否有密钥被写进代码，
  `make check-secrets-history` 扫描全部提交历史。见下面的「不要把凭据提交进仓库」。

需要你自己注意的：

- **明文协议不要暴露在公网**（见上面的协议表）。
- **凭据要保管好**。中转服务端能访问的网段，拿到凭据的人也能访问。
- **控制台默认只监听本机**。要远程访问，请用 SSH 端口转发，而不是
  直接开放端口。
- **自签证书请固定指纹，不要用 `insecure: true`**。`insecure` 是真的不校验
  任何证书，中间人可以直接冒充中转机；只有 `certFingerprint` 才有实际防护，
  见上面的「证书指纹固定」。如果中转机有域名，建议签一张真证书。

### 不要把凭据提交进仓库

配置文件和部署脚本里会同时出现 PSK、UUID、控制台密码哈希，以及
SSH 的明文密码（远程部署要用）。这些东西一旦进了公开仓库的提交，
就必须当作已经泄露——**改写历史也救不回来**，别人可能已经拉走了。
唯一的正确做法是把它们轮换掉。

仓库里做了两层拦截：

```bash
make hooks           # 安装 git 钩子（core.hooksPath=.githooks），只需一次
make check-secrets   # 手动扫一遍当前工作区
make check-secrets-history   # 扫全部提交历史（能发现「提交过又删掉」的密钥）
```

`make lint` 里也带了这次扫描，所以不用靠记忆。

钩子和扫描脚本本身是公开的，所以**真实的密码和地址不写在里面**，而是放在
`.secrets-denylist`（已被 `.gitignore` 忽略，每行一个值，`#` 后面是注释）。
这样扫描器知道要拦哪些值，而它自己仍然可以安全地公开。第一次在新机器上
工作时记得先建这个文件：

```bash
cat > .secrets-denylist <<'EOF'
# 中转机地址
192.0.2.10
# SSH 密码
your-ssh-password
EOF
```

`.gitignore` 还忽略了 `/config.json`、`*.local.json`、`*.log` 和 `/dist/`。
其中 `/dist/`、`/porttransit` 这些**前面带斜杠是故意的**：不加斜杠的
`porttransit` 会连源码目录 `cmd/porttransit/` 一起忽略掉，命令行入口
就从仓库里凭空消失了。

如果扫描真的误报了（比如测试里用了一个明显假的夹具），在该行加注释
`check-secrets:allow` 即可，比放宽整条规则更容易审查。

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

### v1.0.1

**性能**

- **多路复用（mux）**：客户端与中转机之间只保持一条连接，所有转发流作为子流传输。
  浏览器打开一个页面会开几十条短连接，每条都要跨国重新握手（TCP + TLS，通常 2～4 个
  RTT），在 200ms 的线路上握手时间比传输本身还长。开启后第二条连接起不再握手，且所有
  子流共用一个拥塞窗口，丢包线路上比几十个窗口竞争更稳。会话层用
  [hashicorp/yamux](https://github.com/hashicorp/yamux)。
  - 两端各写一次 `"mux": true` 即可，**默认关闭**，不写就和以前完全一样。
  - 子流支持半关闭：一端写完后发 FIN，另一端仍可继续回包。请求/响应类协议（请求发完
    即关闭写侧，然后等服务端回复）不会被截断，也不会退化成「连接挂到空闲超时」。
  - 仅 `direct` / `tls` / `reality` / `ws` / `httpupgrade` 支持（目标地址写在自己协议头里
    的 `vless` / `vmess` / `trojan` / `shadowsocks` / `socks5` 没有连接级命令可以表达会话，
    开了也会自动退回独立连接并提示一次）。
  - 每条子流带自己的前导帧，所以 ACL、账号并发/配额/限速、转发规则**逐子流**生效，
    多路复用不是绕过策略的路径。
  - 中转机侧整个 listener 共享一个防重放窗口（每子流一个会让兄弟子流互相重放）。
  - 参数不一致不会挂住：客户端收到拒绝立即退回独立连接，表现为「慢一点」而不是「连不上」。
- **内核网络调优**：安装时自动开启 BBR 并调整缓冲区、连接队列、本地端口范围等
  15 项参数，写入独立的 `/etc/sysctl.d/99-porttransit.conf`。跨国线路的主要
  瓶颈是丢包，默认的 CUBIC 一遇丢包就把窗口砍半，BBR 不会——这是所有优化里
  提升最明显的一项。
  - 新增 `porttransit tune` 命令：`--show` 预览、`--no-persist` 只本次生效、
    `--revert` 删除配置文件；`install.sh --skip-tune` 可跳过。
  - 逐项独立应用并**读回校验**：容器里只读的参数会如实报告，而不是把没生效的
    报成成功。

**修复**

- **客户端账号策略之前完全不生效**：`server.clients` 里的 `enabled`、
  `maxConnections`、`rateLimitKBps`、`quotaBytes`、`expiresAt` 五个字段
  配置了但从未被检查——「停用」一个客户端后它照样能用。现在全部生效：
  - 停用 / 到期 / 配额用尽 / 并发超限都会拒绝连接，并在日志里说明原因。
  - 一旦配置了账号，**未知的 clientId 会被拒绝**。否则任何人换一个 id 就能
    绕过按客户端的策略，账号功能形同虚设。
  - 用量会持久化到 `dataDir/quota.json`（0600），重启不清零——否则客户端
    等一次重部署就能重置配额。
  - 控制台新增 `/api/v1/accounts`，可查看每个账号的实时并发与累计流量，
    并可重置配额。
- **`server.masking` 配置了但从未应用**：整个 masking 块只被校验、从不生效，
  运营商以为探测处理好了其实没有。现在会合并进 listener 的传输参数
  （listener 自己的设置优先），并对不支持 fallback 的协议给出警告。
- **`resolver` 的自定义 DNS 从未生效**：`servers` / `protocol` / `timeout`
  三个字段之前只用于 `strategy` 判断。现在真正生效，并修掉一个括号 IPv6
  地址被双重加括号导致无法解析的缺陷。
- **`tcpFastOpen` / `mptcp` 从未生效**：现在通过 `ListenConfig.Control` 在
  **bind 之前**设置（对已监听的 socket 设置 TFO 是无效的），非 Linux 平台
  会明确告知已忽略而不是静默失效。
- **入站 PROXY protocol 从未生效**：`listener.proxyProtocol` 之前只是配置项。
  现在支持 v1/v2 解析，让中转机在负载均衡后面也能看到真实客户端地址。
- **浏览器代理现在支持 UDP**：本地 SOCKS5 之前对 `UDP ASSOCIATE` 直接回
  `0x07`，导致浏览器无法通过代理发 DNS 或走 QUIC——只能退回 TCP 并用系统
  解析器，**这会泄漏正在访问的域名**。`client.proxy.udp` 现在生效。
- 修正 README 中关于 UDP 支持范围的过时描述（`direct` 通过前导帧也支持）。

**安全**

- 证书指纹 pin：`settings.certFingerprint`，让自签证书的中转不再必须用
  `insecure: true`（那等于完全不校验服务端）。
- 新增 `porttransit fingerprint` 命令：`--cert <证书文件>` 读本地证书，
  `--server <地址>` 直接连运行中的中转服务端取证书，输出 `key=value` 形式的
  SHA-256 指纹，可以直接抄进客户端的 `certFingerprint`。服务端启动日志里也会
  打一次自己的指纹。
- `settings.fingerprint` 补齐文档：接受 `chrome` / `firefox` / `safari` /
  `edge` / `ios` / `android` / `golang` / `random`（别名 `randomized`）/
  `random-no-alpn` / `none`，其中 `none` 走标准库 `crypto/tls` 握手而不使用
  uTLS。写错档位名会直接报错，不会静默退回默认值。

### v1.0.0 — 首个版本

**传输协议**

- 支持 11 种中转协议：`tls`、`reality`、`vless`、`vmess`、`trojan`、
  `shadowsocks`、`ws`、`httpupgrade`、`http`（HTTP CONNECT）、`socks5`、`direct`
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
- 多线路分组、多种负载均衡策略（`first` / `round-robin` / `random` /
  `least-latency`，服务端转发规则另外支持 `least-conn`）

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

本项目采用 MIT 许可。

多路复用（`mux`）依赖 [hashicorp/yamux](https://github.com/hashicorp/yamux)，
该项目采用 MPL-2.0 许可（文件级弱 copyleft，不影响本项目自身的 MIT 授权）。
