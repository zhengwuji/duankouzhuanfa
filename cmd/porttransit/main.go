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
		path       string
		mode       string
		listen     string
		transport  string
		name       string
		force      bool
		adminPass  string
		adminUser  string
		printCreds bool
	)
	fs.StringVar(&path, "config", defaultConfigPath(), "写入的配置文件路径")
	fs.StringVar(&mode, "mode", "server", "运行模式：server / client / both")
	fs.StringVar(&listen, "listen", "", "中转监听地址，例如 0.0.0.0:8443")
	fs.StringVar(&transport, "transport", "tls", "中转协议")
	fs.StringVar(&name, "name", "", "该中转线路的名称")
	fs.BoolVar(&force, "force", false, "覆盖已存在的配置文件")
	fs.StringVar(&adminUser, "admin-user", "admin", "网页控制台管理员用户名")
	fs.StringVar(&adminPass, "admin-password", "", "网页控制台管理员密码（留空则随机生成）")
	fs.BoolVar(&printCreds, "print-credentials", false, "生成后打印连接凭据（供自动部署读取）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s 已存在；如需覆盖请加 --force", path)
	}

	m := config.Mode(strings.ToLower(mode))
	switch m {
	case config.ModeServer, config.ModeClient, config.ModeBoth:
	default:
		return fmt.Errorf("--mode 只能是 server、client 或 both，收到 %q", mode)
	}

	cfg := config.Default(m)

	// The management password is generated rather than left empty: a console
	// with no password is a console anyone on the host can open, and an
	// operator who is told the generated password will change it, while one
	// who is told "set a password" may not.
	if adminPass == "" {
		adminPass = randomPassword()
	}
	hash, err := hashPassword(adminPass)
	if err != nil {
		return err
	}
	cfg.WebUI.Username = adminUser
	cfg.WebUI.PasswordHash = hash

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
			u := newUUID()
			l.Settings["uuid"] = u
			creds["uuid"] = u
		case "trojan":
			pw := randomPassword()
			l.Settings["password"] = pw
			creds["password"] = pw
			l.Settings["fallbackAddr"] = "www.bing.com:443"
		case "shadowsocks":
			key := generateSSKey(transport)
			l.Settings["method"] = "2022-blake3-chacha20-poly1305"
			l.Settings["password"] = key
			creds["method"] = "2022-blake3-chacha20-poly1305"
			creds["password"] = key
		case "reality":
			priv, pub := generateRealityKeyPair()
			l.Settings["privateKey"] = priv
			l.Settings["shortId"] = generateShortID()
			l.Settings["dest"] = "www.bing.com:443"
			l.Settings["serverNames"] = []string{"www.bing.com"}
			creds["publicKey"] = pub
			creds["shortId"] = fmt.Sprint(l.Settings["shortId"])
			creds["serverName"] = "www.bing.com"
		case "socks5":
			user, pass := "pt", randomPassword()
			l.Settings["username"] = user
			l.Settings["password"] = pass
			creds["username"] = user
			creds["password"] = pass
		}
		creds["psk"] = psk
		creds["transport"] = transport
		creds["listen"] = listen
		creds["name"] = l.Name

		cfg.Server.Listeners = []config.Listener{l}

		// A "both" configuration runs a relay and a client in one process, so
		// the client is wired to the relay that was just generated. Without
		// this the operator has to copy the credentials off the terminal into
		// the console before the proxy does anything, and the console's relay
		// list is empty on a configuration that plainly contains a relay.
		if cfg.Client != nil {
			cfg.Client.Servers = append(cfg.Client.Servers, config.ServerEntry{
				ID:        "srv-local",
				Name:      l.Name + "（本机）",
				Address:   clientAddressFor(listen),
				Transport: transport,
				Enabled:   true,
				Settings:  clientSettingsFor(transport, creds),
			})
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
	fmt.Printf("网页控制台：http://%s\n", cfg.WebUI.Listen)
	fmt.Printf("管理员用户名：%s\n", cfg.WebUI.Username)
	fmt.Printf("管理员密码：%s\n", adminPass)
	fmt.Println()
	fmt.Println("请妥善保存以上密码；配置文件中只保存了密码的哈希值，无法找回。")

	if cfg.Server != nil {
		fmt.Println()
		fmt.Println("中转服务端凭据（客户端连接时需要）：")
		for _, k := range []string{"transport", "listen", "name", "psk", "uuid", "password", "method", "publicKey", "shortId", "serverName", "username"} {
			if v, ok := creds[k]; ok && v != "" {
				fmt.Printf("%s=%s\n", k, v)
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
	fmt.Printf("网页控制台：%v  监听 %s\n", cfg.WebUI.Enabled, cfg.WebUI.Listen)
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

// clientSettingsFor derives the client half of a relay's credentials.
//
// It is a translation rather than a copy: the relay's settings contain its
// private key material (certFile, keyFile, privateKey) which must never reach
// the client, and the client needs fields the relay does not have, such as
// "insecure" for a self-signed certificate.
func clientSettingsFor(transportName string, creds map[string]string) map[string]any {
	s := map[string]any{}
	if psk := creds["psk"]; psk != "" {
		s["psk"] = psk
	}

	switch transportName {
	case "tls", "vless", "vmess", "trojan":
		// The relay's certificate is self-signed and freshly generated, so the
		// client cannot verify it against a CA. It still authenticates the
		// relay through the preamble's PSK, which is what actually protects
		// the link. No serverName is set, so the transport uses the dial host.
		s["insecure"] = true
		switch transportName {
		case "vless", "vmess":
			s["uuid"] = creds["uuid"]
		case "trojan":
			s["password"] = creds["password"]
		}
	case "shadowsocks":
		s["method"] = creds["method"]
		s["password"] = creds["password"]
	case "reality":
		// REALITY is the one scheme whose security depends on the name and the
		// key, so all three fields are mandatory rather than cosmetic.
		s["serverName"] = creds["serverName"]
		s["publicKey"] = creds["publicKey"]
		s["shortId"] = creds["shortId"]
	case "socks5":
		s["username"] = creds["username"]
		s["password"] = creds["password"]
	case "ws", "httpupgrade":
		// These schemes are plain by default on the relay, so the client must
		// not attempt a TLS handshake the relay is not expecting.
		s["tls"] = false
	}
	return s
}

// logxUnused keeps the logx import honest if a future edit removes its only
// use; the CLI constructs loggers through the app package.
var _ = logx.Discard
