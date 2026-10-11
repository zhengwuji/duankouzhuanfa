// Command porttransit is the single binary that runs the relay, the client,
// the management console and the installer.
//
// One binary rather than several is a deliberate choice for this project: the
// installer copies exactly one file to a host, upgrades are a single replace,
// and the client can upload its own executable to deploy a relay that is
// guaranteed to be the same version.
//
// # Subcommands
//
//	run              run the configured role in the foreground
//	server           run only the relay role
//	client           run only the client role
//	init             write a fresh configuration
//	install          install as a systemd service (Linux, needs root)
//	uninstall        remove everything the installer created
//	reset-password   set a new management password
//	show-credentials print the relay's connection details
//	show-console     print the management console's address and username
//	set-console      change the management console's listen address
//	fingerprint      print a relay certificate's SHA-256 fingerprint
//	deploy           install a relay on a remote host over SSH
//	status           print the current configuration's summary
//	version          print build information
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"porttransit/internal/app"
	"porttransit/internal/config"
	"porttransit/internal/install"
	"porttransit/internal/logx"
	"porttransit/internal/version"
)

func main() {
	// The program name is stripped so the usage line reads
	// "porttransit <command>" regardless of the path it was invoked by.
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	cmd := args[0]
	rest := args[1:]

	var err error
	switch cmd {
	case "run":
		err = cmdRun(rest)
	case "server":
		err = cmdRunMode(rest, config.ModeServer)
	case "client":
		err = cmdRunMode(rest, config.ModeClient)
	case "init":
		err = cmdInit(rest)
	case "install":
		err = install.Install(rest)
	case "uninstall":
		err = install.Uninstall(rest)
	case "reset-password":
		err = install.ResetPassword(rest)
	case "show-credentials":
		err = install.ShowCredentials(rest)
	case "show-console":
		err = install.ShowConsole(rest)
	case "set-console":
		err = install.SetConsole(rest)
	case "fingerprint":
		err = install.Fingerprint(rest)
	case "tune":
		err = install.Tune(rest)
	case "deploy":
		err = cmdDeploy(rest)
	case "status":
		err = cmdStatus(rest)
	case "version", "-v", "--version":
		fmt.Println(version.String())
		fmt.Printf("protocol %d\n", version.ProtocolVersion)
		fmt.Printf("go %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `PortTransit — 端口转发 / 中转系统

用法：
  porttransit <命令> [参数]

服务运行：
  run               按配置文件运行（服务端 / 客户端 / 两者）
  server            仅以中转服务端身份运行
  client            仅以客户端身份运行
  status            显示当前配置摘要

配置与安装：
  init              生成一份新的配置文件
  install           安装为系统服务（需要 root）
  uninstall         彻底卸载（删除配置、数据、服务与可执行文件）
  reset-password    重置管理后台管理员密码
  show-credentials  打印中转服务端的连接凭据
  show-console      打印网页控制台的地址与用户名
  set-console       修改网页控制台的监听地址（改成 0.0.0.0:8787 即可用 服务器IP:8787 直接访问）
  fingerprint       计算中转服务端证书的 SHA-256 指纹（用于客户端 certFingerprint）
  tune              应用内核网络调优（BBR 等），中转性能的关键

远程部署：
  deploy            通过 SSH 在一台远程服务器上一键安装中转服务端

其他：
  version           显示版本信息
  help              显示本帮助

示例：
  porttransit init --mode server --listen 0.0.0.0:8443
  porttransit install --transport tls --port 8443
  porttransit deploy --host 1.2.3.4 --user root --transport tls
  porttransit fingerprint --cert /etc/porttransit/certs/relay.crt
  porttransit fingerprint --server relay.example.com:8443
  porttransit reset-password --config /etc/porttransit/config.json
  porttransit set-console --listen 0.0.0.0:8787 --allow-remote   # 控制台外网可访问
  porttransit set-console --listen 127.0.0.1:8787                # 改回仅本机
`)
}

// commonFlags holds the flags every run-like command accepts.
type commonFlags struct {
	configPath string
	mode       config.Mode
	logLevel   string
	logFile    string
	noWebUI    bool
}

// addRunFlags registers the shared flags.
func addRunFlags(fs *flag.FlagSet, cf *commonFlags) {
	fs.StringVar(&cf.configPath, "config", defaultConfigPath(), "配置文件路径")
	fs.StringVar(&cf.logLevel, "log-level", "", "日志级别：debug / info / warn / error")
	fs.StringVar(&cf.logFile, "log-file", "", "日志文件路径，- 表示只输出到终端")
	fs.BoolVar(&cf.noWebUI, "no-webui", false, "禁用网页控制台")
}

// defaultConfigPath picks a sensible default per platform, so the same command
// works on a Linux relay and on a Windows workstation running the client.
func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		if dir, err := os.UserConfigDir(); err == nil {
			return dir + `\porttransit\config.json`
		}
		return "porttransit.json"
	}
	if os.Geteuid() == 0 {
		return app.DefaultConfigPath
	}
	if dir, err := os.UserConfigDir(); err == nil {
		return dir + "/porttransit/config.json"
	}
	return "porttransit.json"
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var cf commonFlags
	addRunFlags(fs, &cf)
	if err := fs.Parse(args); err != nil {
		return err
	}
	return runApp(cf)
}

func cmdRunMode(args []string, mode config.Mode) error {
	fs := flag.NewFlagSet(string(mode), flag.ContinueOnError)
	var cf commonFlags
	addRunFlags(fs, &cf)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cf.mode = mode
	return runApp(cf)
}

// runApp constructs and runs the process, handling the termination signals a
// service manager sends.
func runApp(cf commonFlags) error {
	application, err := app.New(app.Options{
		ConfigPath:   cf.configPath,
		ModeOverride: cf.mode,
		LogLevel:     cf.logLevel,
		LogFile:      cf.logFile,
		NoWebUI:      cf.noWebUI,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The signal handler lives here rather than in app so that app stays a
	// library with no opinion about how it is being run.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	return application.Run(ctx)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var (
		path        string
		mode        string
		listen      string
		transport   string
		name        string
		force       bool
		addListener bool
		adminPass   string
		adminUser   string
		webuiListen string
		allowRemote bool
		printCreds  bool
	)
	fs.StringVar(&path, "config", defaultConfigPath(), "写入的配置文件路径")
	fs.StringVar(&mode, "mode", "server", "运行模式：server / client / both")
	fs.StringVar(&listen, "listen", "", "中转监听地址，例如 0.0.0.0:8443")
	fs.StringVar(&transport, "transport", "tls", "中转协议")
	fs.StringVar(&name, "name", "", "该中转线路的名称")
	fs.BoolVar(&force, "force", false, "覆盖已存在的配置文件")
	fs.BoolVar(&addListener, "add-listener", false, "在现有配置中追加一条中转监听，而不是覆盖整个配置")
	fs.StringVar(&adminUser, "admin-user", "admin", "网页控制台管理员用户名")
	fs.StringVar(&adminPass, "admin-password", "", "网页控制台管理员密码（留空则随机生成）")
	fs.StringVar(&webuiListen, "webui-listen", "", "网页控制台监听地址，例如 0.0.0.0:8787（默认 127.0.0.1:8787）")
	fs.BoolVar(&allowRemote, "webui-allow-remote", false, "允许网页控制台绑定非回环地址（等于把管理后台暴露在网络上）")
	fs.BoolVar(&printCreds, "print-credentials", false, "生成后打印连接凭据（供自动部署读取）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Which flags the caller actually named, as opposed to which ones carry a
	// default. Appending a listener must not disturb the account or the mode,
	// so those two are only touched when they were asked for by name.
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	exists := false
	if _, err := os.Stat(path); err == nil {
		exists = true
	}

	if addListener && force {
		return errors.New("--add-listener 与 --force 互斥：前者在现有配置上追加，后者覆盖它")
	}
	if exists && !force && !addListener {
		return fmt.Errorf("%s 已存在；如需覆盖请加 --force，如需追加线路请加 --add-listener", path)
	}
	if addListener && !exists {
		return fmt.Errorf("%s 不存在，无法追加线路；去掉 --add-listener 可直接创建新配置", path)
	}

	m := config.Mode(strings.ToLower(mode))
	switch m {
	case config.ModeServer, config.ModeClient, config.ModeBoth:
	default:
		return fmt.Errorf("--mode 只能是 server、client 或 both，收到 %q", mode)
	}

	var cfg *config.Config
	if addListener {
		loaded, err := config.Load(path)
		if err != nil {
			return err
		}
		cfg = loaded
		if cfg.Server == nil {
			return fmt.Errorf("--add-listener 需要服务端配置，但 %s 没有 server 段", path)
		}
		if set["mode"] && cfg.Mode != m {
			return fmt.Errorf("--add-listener 不能更改运行模式（现有 %s，请求 %s）：追加线路必须保留其余设置", cfg.Mode, m)
		}
	} else {
		cfg = config.Default(m)
		// config.Default seeds a placeholder listener (relay-tls on 0.0.0.0:8443)
		// so a hand-written configuration has an example to follow. It is not
		// operator intent, and leaving it in place while adding the requested
		// line would bind a TLS relay nobody asked for — and, when the request
		// itself is tls on 8443, collide with the placeholder. A fresh
		// generation starts from an empty list.
		if cfg.Server != nil {
			cfg.Server.Listeners = nil
		}
	}

	// The management password is generated rather than left empty: a console
	// with no password is a console anyone on the host can open, and an
	// operator who is told the generated password will change it, while one
	// who is told "set a password" may not.
	//
	// Appending a listener is the exception, and it preserves the existing
	// hash. Regenerating it would silently lock the operator out of a console
	// they are already using — and the replacement would never even be seen,
	// because the deployment path reads credentials back and never looks at
	// the console password.
	adminPassReport := ""
	switch {
	case adminPass != "":
		hash, err := hashPassword(adminPass)
		if err != nil {
			return err
		}
		cfg.WebUI.PasswordHash = hash
		adminPassReport = adminPass
	case addListener:
		adminPassReport = "未更改（沿用现有配置）"
	default:
		pw := randomPassword()
		hash, err := hashPassword(pw)
		if err != nil {
			return err
		}
		cfg.WebUI.PasswordHash = hash
		adminPassReport = pw
	}
	if !addListener || set["admin-user"] {
		cfg.WebUI.Username = adminUser
	}

	// Exposing the console is opt-in and always explicit.
	//
	// config.Validate refuses a non-loopback listen without AllowRemote, so the
	// acknowledgement and the address travel together: an operator who asks for
	// a public console gets one, and nobody gets one by accident.
	//
	// On the append path these are left alone unless named, for the same reason
	// the password is: adding a relay line must not silently move or expose a
	// console the operator is already using.
	if webuiListen != "" {
		cfg.WebUI.Listen = webuiListen
	}
	if allowRemote {
		cfg.WebUI.AllowRemote = true
	}
	// A public console without a password is refused by Validate; catching it
	// here names the flag that caused it.
	if !config.IsLoopbackListen(cfg.WebUI.Listen) && !cfg.WebUI.AllowRemote {
		return fmt.Errorf("--webui-listen %s 不是回环地址；把管理后台暴露到网络上必须显式加 --webui-allow-remote", cfg.WebUI.Listen)
	}

	creds := map[string]string{}

	if cfg.Server != nil {
		if listen == "" {
			listen = "0.0.0.0:" + fmt.Sprint(defaultPortFor(transport))
		}
		l := config.Listener{
			Name:      firstNonEmpty(name, "relay-"+transport),
			Transport: transport,
			Listen:    listen,
			Enabled:   true,
			Settings:  map[string]any{},
		}
		// A pre-shared key authenticates the PortTransit preamble for the
		// transports that use it, so one is generated for every scheme: an
		// unauthenticated listener is an open relay.
		psk := generatePSK()
		l.Settings["psk"] = psk

		switch transport {
		case "tls":
			// A self-signed certificate is generated on first use by the
			// transport, so only the paths need recording.
			l.Settings["certFile"] = "/etc/porttransit/certs/relay.crt"
			l.Settings["keyFile"] = "/etc/porttransit/certs/relay.key"
		case "vless", "vmess":
			l.Settings["uuid"] = newUUID()
		case "trojan":
			l.Settings["password"] = randomPassword()
			l.Settings["fallbackAddr"] = "www.bing.com:443"
		case "shadowsocks":
			l.Settings["method"] = "2022-blake3-chacha20-poly1305"
			l.Settings["password"] = generateSSKey(transport)
		case "reality":
			priv, _ := generateRealityKeyPair()
			l.Settings["privateKey"] = priv
			l.Settings["shortId"] = generateShortID()
			l.Settings["dest"] = "www.bing.com:443"
			l.Settings["serverNames"] = []string{"www.bing.com"}
		case "socks5":
			l.Settings["username"] = "pt"
			l.Settings["password"] = randomPassword()
		}

		// Listeners are appended, never replaced. Replacing them meant that
		// running this command — which is exactly what the remote deployment
		// path runs — silently deleted every relay already configured on the
		// host, while the deployment still reported success. An operator
		// adding a second line to a server would lose the first one.
		//
		// Re-adding the same endpoint is treated as an update, so a repeated
		// deployment repairs its own line instead of accumulating duplicates
		// that cannot bind the port they both claim.
		replaced := false
		for i := range cfg.Server.Listeners {
			if cfg.Server.Listeners[i].Name != l.Name {
				continue
			}
			// Reusing the credentials is what makes a re-run a *repair*. A
			// fresh PSK for an existing line would silently invalidate every
			// client already configured with the old one — and the deployment
			// that did it would still report success. Only the transport's own
			// settings are preserved: the listen address and the enabled flag
			// come from this invocation, so moving a line to another port still
			// works.
			//
			// A changed transport must regenerate them, because the settings
			// are scheme-specific and a UUID means nothing to trojan.
			if cfg.Server.Listeners[i].Transport == l.Transport {
				if prev := cfg.Server.Listeners[i].Settings; len(prev) > 0 {
					l.Settings = prev
				}
			}
			cfg.Server.Listeners[i] = l
			replaced = true
			break
		}
		// A listener whose port is already claimed by a *different* line would
		// fail to bind, and the failure would only appear in the relay's log.
		// Catch it while the operator is still watching. The check runs whether
		// the line was appended or replaced, because an update can move a line
		// onto a port another line already owns.
		for _, other := range cfg.Server.Listeners {
			if other.Name != l.Name && other.Listen == l.Listen {
				return fmt.Errorf("端口 %s 已被线路 %q 使用；请换一个 --listen 或 --port", l.Listen, other.Name)
			}
		}
		if !replaced {
			cfg.Server.Listeners = append(cfg.Server.Listeners, l)
		}

		// The credentials are derived from the listener rather than assembled
		// alongside it, so this path and `show-credentials` cannot disagree
		// about what a client needs. They used to: init printed a reality
		// relay's public key and show-credentials did not, which made a relay
		// installed by the one-click script impossible to add to a client.
		creds = install.ListenerCredentials(l)

		// A "both" configuration runs a relay and a client in one process, so
		// the client is wired to the relay that was just generated. Without
		// this the operator has to copy the credentials off the terminal into
		// the console before the proxy does anything, and the console's relay
		// list is empty on a configuration that plainly contains a relay.
		//
		// The local client entry is keyed by the listener name for the same
		// reason: re-adding a line must update its client half rather than
		// leaving a stale entry pointing at the credentials it just replaced.
		if cfg.Client != nil {
			localID := "srv-local"
			if l.Name != "" {
				localID = "srv-local-" + l.Name
			}
			entry := config.ServerEntry{
				ID:        localID,
				Name:      l.Name + "（本机）",
				Address:   clientAddressFor(listen),
				Transport: transport,
				Enabled:   true,
				Settings:  install.ClientSettingsFor(transport, creds),
			}
			found := false
			for i := range cfg.Client.Servers {
				if cfg.Client.Servers[i].ID == localID {
					cfg.Client.Servers[i] = entry
					found = true
					break
				}
			}
			if !found {
				cfg.Client.Servers = append(cfg.Client.Servers, entry)
			}
		}
	}

	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := cfg.Save(path); err != nil {
		return err
	}

	fmt.Printf("已写入配置：%s\n", path)
	fmt.Printf("运行模式：%s\n", cfg.Mode)
	// The console URL is printed as something an operator can paste into a
	// browser. A wildcard bind address is not one: "http://0.0.0.0:8787" is
	// not a destination, and it was what the one-click installer used to show.
	fmt.Printf("网页控制台：%s\n", consoleURL(cfg.WebUI.Listen))
	fmt.Printf("管理员用户名：%s\n", cfg.WebUI.Username)
	fmt.Printf("管理员密码：%s\n", adminPassReport)
	if cfg.Server != nil {
		fmt.Printf("中转线路：%d 条\n", len(cfg.Server.Listeners))
	}
	fmt.Println()
	if adminPassReport == "未更改（沿用现有配置）" {
		fmt.Println("管理员密码未被修改。")
	} else {
		fmt.Println("请妥善保存以上密码；配置文件中只保存了密码的哈希值，无法找回。")
	}

	if cfg.Server != nil {
		fmt.Println()
		fmt.Println("中转服务端凭据（客户端连接时需要）：")
		for _, key := range install.CredentialKeyOrder {
			if v, ok := creds[key]; ok && v != "" {
				fmt.Printf("%s=%s\n", key, v)
			}
		}
	}
	_ = printCreds
	return nil
}

func cmdDeploy(args []string) error {
	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	var (
		host      string
		port      int
		user      string
		auth      string
		keyPath   string
		password  string
		transport string
		relayPort int
		name      string
		binary    string
		dlURL     string
		addTo     string
	)
	fs.StringVar(&host, "host", "", "远程服务器地址（必填）")
	fs.IntVar(&port, "ssh-port", 22, "SSH 端口")
	fs.StringVar(&user, "user", "root", "SSH 用户名")
	fs.StringVar(&auth, "auth", "key", "SSH 认证方式：key / password")
	fs.StringVar(&keyPath, "key", "", "SSH 私钥路径")
	fs.StringVar(&password, "password", "", "SSH 密码（使用密码认证时）")
	fs.StringVar(&transport, "transport", "tls", "中转协议")
	fs.IntVar(&relayPort, "port", 8443, "中转监听端口")
	fs.StringVar(&name, "name", "", "线路名称")
	fs.StringVar(&binary, "binary", "", "上传的服务端程序（默认使用本程序，若不是 Linux 构建会自动查找同目录下的匹配版本）")
	fs.StringVar(&dlURL, "download-url", "", "服务器自行下载服务端程序的地址，支持 {os}/{arch} 占位符")
	fs.StringVar(&addTo, "add-to", "", "部署成功后写入的客户端配置文件")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if host == "" {
		return errors.New("必须提供 --host")
	}
	return install.DeployRemote(install.DeployOptions{
		Host:            host,
		Port:            port,
		Username:        user,
		AuthMethod:      auth,
		PrivateKeyPath:  keyPath,
		Password:        password,
		Transport:       transport,
		RelayPort:       relayPort,
		Name:            name,
		LocalBinaryPath: binary,
		DownloadURL:     dlURL,
		AddToConfig:     addTo,
	})
}

// consoleURL renders a webui listen address as a URL an operator can paste
// into a browser.
//
// The rule lives in the install package because the one-click script reports
// the same address through `show-console`; two copies would be two answers to
// "what URL do I open".
func consoleURL(listen string) string {
	return install.ConsoleURL(listen, false)
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	path := fs.String("config", defaultConfigPath(), "配置文件路径")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}

	fmt.Printf("配置文件：%s\n", *path)
	fmt.Printf("运行模式：%s\n", cfg.Mode)
	fmt.Printf("日志级别：%s\n", cfg.Log.Level)
	fmt.Printf("网页控制台：%v  %s\n", cfg.WebUI.Enabled, consoleURL(cfg.WebUI.Listen))
	fmt.Println()

	if cfg.Server != nil {
		fmt.Printf("中转监听（%d 个）：\n", len(cfg.Server.Listeners))
		for _, l := range cfg.Server.Listeners {
			state := "已启用"
			if !l.Enabled {
				state = "已停用"
			}
			fmt.Printf("  - %-16s %-12s %-22s %s\n", l.Name, l.Transport, l.Listen, state)
		}
		fmt.Printf("转发规则：%d 个\n", len(cfg.Server.Forwards))
		fmt.Printf("客户端账号：%d 个\n", len(cfg.Server.Clients))
		fmt.Println()
	}

	if cfg.Client != nil {
		fmt.Printf("中转服务器（%d 个）：\n", len(cfg.Client.Servers))
		for _, s := range cfg.Client.Servers {
			state := "已启用"
			if !s.Enabled {
				state = "已停用"
			}
			fmt.Printf("  - %-16s %-12s %-24s %s\n", firstNonEmpty(s.Name, s.ID), s.Transport, s.Address, state)
		}
		fmt.Printf("端口转发规则：%d 个\n", len(cfg.Client.Tunnels))
		fmt.Printf("本地代理：%v  SOCKS5=%s  HTTP=%s\n",
			cfg.Client.Proxy.Enabled, cfg.Client.Proxy.SOCKS5Listen, cfg.Client.Proxy.HTTPListen)
		fmt.Println()
	}
	return nil
}

// clientAddressFor turns a relay listen address into the address a co-located
// client should dial.
//
// A wildcard bind is rewritten to the loopback address: the client in a "both"
// configuration runs in the same process as the relay, and "0.0.0.0:8443" is
// not a dialable destination. A specific bind address is kept, because the
// operator who bound to one interface meant it.
func clientAddressFor(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

// clientSettingsFor is kept as a thin alias so the tests that pin the client
// translation keep asserting against the one implementation that ships.
//
// The real work lives in install.ClientSettingsFor, which the console's deploy
// path also uses. Two copies of this logic is what previously let a deployed
// relay land in a client without the "insecure"/"tls" fields it needs.
func clientSettingsFor(transportName string, creds map[string]string) map[string]any {
	return install.ClientSettingsFor(transportName, creds)
}

// logxUnused keeps the logx import honest if a future edit removes its only
// use; the CLI constructs loggers through the app package.
var _ = logx.Discard
