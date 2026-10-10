// Package install implements the one-click install, uninstall, password reset
// and remote deployment paths.
//
// It is separate from the CLI so that the same code can be driven from the
// management console's "deploy a relay" button, and so that the destructive
// operations live in one auditable file. Anything that deletes a file or
// rewrites a service unit is here.
package install

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/transports/reality"
)

// Paths the installer owns.
//
// Uninstall removes exactly these and nothing else: a relay host often runs
// other services, and an uninstaller that sweeps a directory it did not create
// is how a maintenance window becomes an outage.
const (
	BinPath    = "/usr/local/bin/porttransit"
	ConfigDir  = "/etc/porttransit"
	ConfigPath = "/etc/porttransit/config.json"
	CertsDir   = "/etc/porttransit/certs"
	DataDir    = "/var/lib/porttransit"
	LogDir     = "/var/log/porttransit"
	UnitPath   = "/etc/systemd/system/porttransit.service"
	UnitName   = "porttransit"
	// SysctlPath holds the relay's kernel tuning. A dedicated file rather than
	// appending to /etc/sysctl.conf so uninstalling removes exactly what was
	// added and never overwrites settings the operator maintains by hand.
	SysctlPath = "/etc/sysctl.d/99-porttransit.conf"
)

// ErrNotLinux reports an install attempted on a platform without systemd.
var ErrNotLinux = errors.New("install: the service installer requires Linux with systemd")

// Install runs the local installation.
func Install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	var (
		transport   string
		listen      string
		name        string
		mode        string
		force       bool
		skipService bool
		skipTune    bool
		adminPass   string
		adminUser   string
	)
	fs.StringVar(&transport, "transport", "tls", "中转协议")
	fs.StringVar(&listen, "listen", "", "中转监听地址（默认 0.0.0.0:<协议默认端口>）")
	fs.StringVar(&name, "name", "", "线路名称")
	fs.StringVar(&mode, "mode", "server", "运行模式：server / client / both")
	fs.BoolVar(&force, "force", false, "覆盖已有配置")
	fs.BoolVar(&skipService, "no-service", false, "只写配置，不安装系统服务")
	fs.BoolVar(&skipTune, "no-tune", false, "跳过内核网络调优（BBR 等）")
	fs.StringVar(&adminUser, "admin-user", "admin", "网页控制台管理员用户名")
	fs.StringVar(&adminPass, "admin-password", "", "网页控制台管理员密码（留空则随机生成）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w (this host is %s)", ErrNotLinux, runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("install: 需要 root 权限，请使用 sudo 运行")
	}

	fmt.Println("==> 创建目录")
	for _, dir := range []string{ConfigDir, CertsDir, DataDir, LogDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}

	fmt.Println("==> 安装可执行文件")
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate the running executable: %w", err)
	}
	// Installing a copy of the running binary rather than expecting one at a
	// fixed path is what makes "curl … | bash" work: the script downloads the
	// binary somewhere temporary and runs it, so the temporary path is the
	// authoritative one.
	if err := copyFile(self, BinPath, 0o755); err != nil {
		return fmt.Errorf("install binary: %w", err)
	}
	fmt.Printf("    %s\n", BinPath)

	if _, err := os.Stat(ConfigPath); err == nil && !force {
		fmt.Printf("==> 配置已存在，保留：%s\n", ConfigPath)
	} else {
		fmt.Println("==> 生成配置")
		initArgs := []string{
			"init",
			"--config", ConfigPath,
			"--mode", mode,
			"--transport", transport,
			"--admin-user", adminUser,
			"--force",
		}
		if listen != "" {
			initArgs = append(initArgs, "--listen", listen)
		}
		if name != "" {
			initArgs = append(initArgs, "--name", name)
		}
		if adminPass != "" {
			initArgs = append(initArgs, "--admin-password", adminPass)
		}
		cmd := exec.Command(BinPath, initArgs...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("generate configuration: %w", err)
		}
		if err := os.Chmod(ConfigPath, 0o600); err != nil {
			return fmt.Errorf("restrict %s: %w", ConfigPath, err)
		}
	}

	if skipService {
		fmt.Println("==> 已跳过系统服务安装")
		return nil
	}

	// Tune before starting the service so it comes up on the tuned parameters
	// rather than picking them up only on the next restart.
	if !skipTune {
		fmt.Println("==> 内核网络调优")
		res, err := TuneKernel(true)
		if err != nil {
			// A host that refuses tuning is still a working relay; report it
			// and continue rather than failing an otherwise good install.
			fmt.Printf("    ! %v\n", err)
		} else {
			fmt.Printf("    %s\n", res.Summary())
			if res.Path != "" {
				fmt.Printf("    %s\n", res.Path)
			}
			for _, line := range res.SkippedList() {
				fmt.Printf("    ! %s\n", line)
			}
		}
	}

	fmt.Println("==> 安装 systemd 服务")
	if err := writeUnit(); err != nil {
		return err
	}

	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--now", UnitName); err != nil {
		return err
	}

	// Report the actual state rather than assuming the start worked: a unit
	// that is enabled but failed to start looks identical to a healthy one
	// from `systemctl enable`'s exit code.
	time.Sleep(700 * time.Millisecond)
	if out, err := exec.Command("systemctl", "is-active", UnitName).Output(); err != nil || strings.TrimSpace(string(out)) != "active" {
		fmt.Println("!! 服务未能启动，最近日志：")
		logCmd := exec.Command("journalctl", "-u", UnitName, "-n", "30", "--no-pager")
		logCmd.Stdout = os.Stdout
		logCmd.Stderr = os.Stderr
		_ = logCmd.Run()
		return errors.New("install: 服务启动失败，请检查上面的日志")
	}

	fmt.Println()
	fmt.Println("✔ 安装完成")
	fmt.Printf("  服务：systemctl status %s\n", UnitName)
	fmt.Printf("  配置：%s\n", ConfigPath)
	fmt.Printf("  日志：journalctl -u %s -f\n", UnitName)
	fmt.Println("  控制台：请查看上面的初始密码，或运行 porttransit reset-password")
	return nil
}

// writeUnit writes the systemd unit.
func writeUnit() error {
	unit := `[Unit]
Description=PortTransit 端口转发 / 中转服务
Documentation=https://github.com/zhengwuji/duankouzhuanfa
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + BinPath + ` run --config ` + ConfigPath + `
Restart=always
RestartSec=3
# A relay holds one file descriptor per connection, so the default soft limit
# of 1024 is far too low for anything beyond a handful of users.
LimitNOFILE=1048576
# The relay only needs to bind a privileged port; everything else is denied so
# a bug in a transport cannot be escalated into a host compromise.
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
ReadWritePaths=` + DataDir + ` ` + LogDir + ` ` + ConfigDir + `
# systemd sets no HOME, and the console's remote-deployment feature stores the
# SSH host keys it trusts under $HOME/.ssh/known_hosts. Without this the store
# has no writable home to live in, and the service runs with a working directory
# of "/" under ProtectSystem=strict. The data directory is already writable and
# is the right place for a daemon's own state, so it doubles as the home.
Environment=HOME=` + DataDir + `
StandardOutput=append:` + LogDir + `/porttransit.log
StandardError=append:` + LogDir + `/porttransit.log

[Install]
WantedBy=multi-user.target
`
	if err := os.WriteFile(UnitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", UnitPath, err)
	}
	fmt.Printf("    %s\n", UnitPath)
	return nil
}

// Uninstall removes everything the installer created.
func Uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	var (
		yes      bool
		keepData bool
	)
	fs.BoolVar(&yes, "yes", false, "不询问，直接卸载")
	fs.BoolVar(&keepData, "keep-data", false, "保留配置与数据目录")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w (this host is %s)", ErrNotLinux, runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return errors.New("uninstall: 需要 root 权限，请使用 sudo 运行")
	}

	if !yes {
		fmt.Println("即将彻底卸载 PortTransit，包括：")
		fmt.Println("  - 停止并删除系统服务")
		fmt.Println("  - 删除可执行文件", BinPath)
		if !keepData {
			fmt.Println("  - 删除配置目录", ConfigDir)
			fmt.Println("  - 删除数据目录", DataDir)
			fmt.Println("  - 删除日志目录", LogDir)
		}
		fmt.Print("\n确认继续？输入 yes 回车：")
		var answer string
		fmt.Scanln(&answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "yes" {
			fmt.Println("已取消。")
			return nil
		}
	}

	fmt.Println("==> 停止服务")
	_ = systemctl("stop", UnitName)
	_ = systemctl("disable", UnitName)

	// A running process that survived the stop would keep the port bound and
	// make a reinstall fail with a confusing address-in-use error, so it is
	// killed explicitly.
	_ = exec.Command("pkill", "-f", BinPath+" run").Run()

	fmt.Println("==> 删除服务单元")
	if err := os.Remove(UnitPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    ! 无法删除 %s: %v\n", UnitPath, err)
	} else {
		fmt.Printf("    %s\n", UnitPath)
	}
	_ = systemctl("daemon-reload")
	_ = systemctl("reset-failed", UnitName)

	fmt.Println("==> 删除可执行文件")
	if err := os.Remove(BinPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("    ! 无法删除 %s: %v\n", BinPath, err)
	} else {
		fmt.Printf("    %s\n", BinPath)
	}

	// Remove the tuning file so a later reinstall or reboot does not keep
	// applying settings the operator believes were uninstalled. The values
	// currently in effect stay until reboot: sysctl cannot restore an unknown
	// previous value, and guessing one could break the host or overwrite
	// settings the operator maintains.
	if err := os.Remove(SysctlPath); err == nil {
		fmt.Println("==> 删除内核调优配置")
		fmt.Printf("    %s\n", SysctlPath)
		fmt.Println("    当前生效的内核参数仍是调优值，重启后恢复系统默认")
	} else if !os.IsNotExist(err) {
		fmt.Printf("    ! 无法删除 %s: %v\n", SysctlPath, err)
	}

	if !keepData {
		fmt.Println("==> 删除配置与数据")
		for _, dir := range []string{ConfigDir, DataDir, LogDir} {
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("    ! 无法删除 %s: %v\n", dir, err)
			} else {
				fmt.Printf("    %s\n", dir)
			}
		}
	}

	fmt.Println()
	fmt.Println("✔ 卸载完成")
	if keepData {
		fmt.Printf("  已保留配置与数据：%s %s %s\n", ConfigDir, DataDir, LogDir)
	}
	return nil
}

// ResetPassword sets a new management console password.
func ResetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	var (
		path     string
		password string
		username string
		generate bool
	)
	fs.StringVar(&path, "config", ConfigPath, "配置文件路径")
	fs.StringVar(&password, "password", "", "新密码（留空则随机生成）")
	fs.StringVar(&username, "username", "", "新的管理员用户名（留空则保持不变）")
	fs.BoolVar(&generate, "generate", true, "密码留空时随机生成")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	if password == "" {
		if !generate {
			return errors.New("reset-password: 必须提供 --password")
		}
		password = randomPassword()
	}
	if len(password) < 8 {
		return errors.New("reset-password: 密码至少需要 8 位")
	}

	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	cfg.WebUI.PasswordHash = hash
	if username != "" {
		cfg.WebUI.Username = username
	}

	if err := cfg.Save(path); err != nil {
		return err
	}

	fmt.Println("✔ 管理员密码已重置")
	fmt.Printf("  用户名：%s\n", cfg.WebUI.Username)
	fmt.Printf("  新密码：%s\n", password)
	fmt.Println()
	fmt.Println("请妥善保存。如果服务正在运行，需要重启才能生效：")
	fmt.Printf("  systemctl restart %s\n", UnitName)
	return nil
}

// ShowCredentials prints the relay's connection details.
//
// It exists because the init output scrolls away, and an operator adding a
// relay to a client needs the credential again long after installation. The
// output is one `key=value` per line so the remote deployment path can parse it
// on a host that has no JSON tooling.
func ShowCredentials(args []string) error {
	fs := flag.NewFlagSet("show-credentials", flag.ContinueOnError)
	var (
		path   string
		name   string
		asJSON bool
	)
	fs.StringVar(&path, "config", ConfigPath, "配置文件路径")
	fs.StringVar(&name, "name", "", "只输出该名称的中转监听（默认第一条已启用的）")
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出（保留兼容；默认输出 key=value）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Server == nil {
		return errors.New("show-credentials: 该配置不是服务端模式")
	}

	// key=value is the primary format because the deployment helper reads it
	// with a shell loop, and a JSON parser is not guaranteed to exist on a
	// minimal server image.
	for _, l := range cfg.Server.Listeners {
		if !l.Enabled {
			continue
		}
		// A named lookup has to be able to find a listener that is not the
		// first one. Without this the deployment path, which reads the
		// credentials back after adding a line, would report the credentials
		// of whichever relay happened to be configured first — and wire the
		// client to an endpoint the operator never asked for.
		if name != "" && l.Name != name {
			continue
		}
		creds := ListenerCredentials(l)
		// A stable order so the output can be diffed between runs.
		for _, key := range CredentialKeyOrder {
			if v, ok := creds[key]; ok && v != "" {
				fmt.Printf("%s=%v\n", key, v)
			}
		}
		// Without a name only the first enabled listener is reported: a client
		// entry names one endpoint, and an operator adding a second one can
		// read the config.
		return nil
	}
	if name != "" {
		return fmt.Errorf("show-credentials: 没有名为 %q 的已启用中转监听", name)
	}
	return errors.New("show-credentials: 没有已启用的中转监听")
}

// CredentialKeyOrder fixes the order credentials are printed in, so the output
// can be diffed between runs and read by eye.
var CredentialKeyOrder = []string{
	"transport", "listen", "name",
	"psk", "uuid", "password", "method",
	"publicKey", "shortId", "serverName",
	"username", "network", "path", "flow", "fingerprint",
}

// ShowConsole prints everything needed to open the management console, as
// key=value lines.
//
// It exists so the one-click installer can report the console address, the
// username and the freshly generated password without embedding a JSON parser
// or re-deriving the URL rule. The password is deliberately absent: the config
// only stores a bcrypt hash, so the plaintext exists solely in the output of
// the `init` run that created it. The installer therefore reads the URL and the
// username from here and takes the password from that run.
func ShowConsole(args []string) error {
	fs := flag.NewFlagSet("show-console", flag.ContinueOnError)
	var (
		path   string
		asJSON bool
	)
	fs.StringVar(&path, "config", ConfigPath, "配置文件路径")
	fs.BoolVar(&asJSON, "json", false, "以 JSON 输出（保留兼容；默认输出 key=value）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	fmt.Printf("enabled=%v\n", cfg.WebUI.Enabled)
	fmt.Printf("listen=%s\n", cfg.WebUI.Listen)
	fmt.Printf("url=%s\n", ConsoleURL(cfg.WebUI.Listen, cfg.WebUI.TLS))
	fmt.Printf("username=%s\n", cfg.WebUI.Username)
	fmt.Printf("tls=%v\n", cfg.WebUI.TLS)
	return nil
}

// ConsoleURL renders a webui listen address as a browsable URL.
//
// A wildcard bind is not a destination: "http://0.0.0.0:8787" names no host.
// For a wildcard bind an address a remote browser can actually reach is
// substituted; when none can be determined the loopback URL is reported, which
// is at least true locally.
//
// Exported so the command line and the installer cannot disagree about what
// address to print.
func ConsoleURL(listen string, useTLS bool) string {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return scheme + "://" + listen
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		if ip := reachableIP(); ip != "" {
			return scheme + "://" + net.JoinHostPort(ip, port)
		}
		host = "127.0.0.1"
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// reachableIP returns an address a remote browser could use to reach this
// host, or "" when only loopback is available.
func reachableIP() string {
	ip := OutboundIP()
	if ip == "" {
		return ""
	}
	if !isPrivateIP(ip) {
		return ip
	}
	// The host is behind NAT: its interface address is on a private range, so
	// it is no more reachable from outside than the wildcard it replaced.
	// Reporting it would send the operator to an address their browser cannot
	// open, which is exactly the problem this function exists to avoid.
	// Asking an external service is the only way to learn the address the
	// world actually sees.
	if pub := PublicIP(); pub != "" {
		return pub
	}
	// No public address could be learned. The private one is still correct for
	// an operator on the same LAN, so it is reported rather than dropped — and
	// the installer says out loud that it is a local address.
	return ip
}

// isPrivateIP reports whether an address is on a range that is not routable
// from the public internet.
func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return true
	}
	for _, cidr := range privateRanges {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

var privateRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, s := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
		"100.64.0.0/10",  // CGNAT, used by carrier NAT
		"169.254.0.0/16", // link local
		"fc00::/7",       // IPv6 unique local
	} {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// PublicIP asks a well-known service for this host's public address.
//
// It is best-effort and bounded: the installer is already downloading a binary
// over the network, so one more short request is not a new dependency, but a
// host with no outbound access must not be made to wait. An empty result means
// "could not determine", never a guess.
//
// It is a variable so tests can substitute a deterministic answer: a unit test
// must not depend on an external service being reachable, or it turns a
// network outage into a red build.
var PublicIP = func() string {
	client := &http.Client{Timeout: 3 * time.Second}
	for _, url := range publicIPServices {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(string(body)))
		if ip == nil || ip.IsLoopback() || isPrivateIP(ip.String()) {
			// A service that answers with a private or malformed address is not
			// telling the truth about this host, so it is not used.
			continue
		}
		return ip.String()
	}
	return ""
}

// publicIPServices are asked in order. Two are listed because a single service
// being blocked or down must not silently degrade the printed URL.
var publicIPServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
}

// OutboundIP reports the address this host would use to reach the internet.
//
// A UDP "connection" performs no handshake and sends no packet: it only makes
// the kernel pick a source address for the route, which is the interface a
// remote client lands on. It returns "" when there is no route, so a host
// without internet access still gets a usable loopback URL rather than an
// error.
func OutboundIP() string {
	c, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer c.Close()
	if addr, ok := c.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String()
	}
	return ""
}

// ClientSettingsFor derives the client half of a relay's credentials.
//
// It is a translation rather than a copy, and it is shared by every path that
// wires a client to a relay — `init --mode both`, the console's "deploy a
// relay" button, and anything added later. That sharing is the point: the two
// paths used to differ, and the difference was invisible until a connection
// failed on the user's machine.
//
// Two things happen here, and both are needed:
//
//  1. Only client-relevant fields are carried over. The relay's settings hold
//     its private key material (privateKey, certFile, keyFile), and copying
//     them wholesale would write a relay's private key into the client half of
//     a file the console displays. The allowlist is what makes that impossible
//     rather than merely unlikely.
//  2. Fields the relay does not have are added: "insecure" for a freshly
//     generated self-signed certificate, and "tls": false for the schemes the
//     relay serves in the clear. A client entry that records the address and
//     key correctly but omits these fails every handshake, which is a
//     configuration error that only shows up as a timeout.
func ClientSettingsFor(transportName string, creds map[string]string) map[string]any {
	s := map[string]any{}

	// clientCredentialKeys are the fields a client authenticates or frames
	// with. Anything not listed here is deliberately not carried over, because
	// the same map holds the relay's private material.
	for _, key := range []string{
		"psk", "uuid", "password", "method",
		"publicKey", "shortId", "serverName",
		"username", "network", "path", "flow",
		"fingerprint", "certFingerprint",
	} {
		if v := creds[key]; v != "" {
			s[key] = v
		}
	}

	switch transportName {
	case "tls", "vless", "vmess", "trojan":
		// The relay's certificate is self-signed and freshly generated, so the
		// client cannot verify it against a CA. It still authenticates the
		// relay through the preamble's PSK, which is what actually protects
		// the link.
		//
		// A pinned fingerprint (certFingerprint) would be strictly better than
		// insecure, but it cannot be known here: the certificate does not exist
		// until the relay's first handshake generates it. An operator who has
		// that fingerprint can set it explicitly, and it takes precedence.
		if s["certFingerprint"] == nil {
			s["insecure"] = true
		}
	case "ws", "httpupgrade":
		// These schemes are plain by default on the relay, so the client must
		// not attempt a TLS handshake the relay is not expecting. Both default
		// to TLS on the client side, so leaving this unset makes the client
		// wait for a ServerHello that never comes.
		s["tls"] = false
	}
	return s
}

// ListenerCredentials derives everything a client needs from one relay
// listener, as a flat key/value map.
//
// It is exported and shared with the console's deploy path because the two used
// to disagree: `init` printed a reality relay's public key while
// `show-credentials` did not, so a relay installed by the one-click script
// could not be added to a client afterwards — the key was printed once and then
// unrecoverable. Deriving the public key from the stored private key is what
// makes that recoverable, and putting the logic in one place is what stops the
// two paths drifting again.
func ListenerCredentials(l config.Listener) map[string]string {
	creds := map[string]string{
		"transport": l.Transport,
		"listen":    l.Listen,
		"name":      l.Name,
	}

	// Anything the transport itself calls a credential is passed through. The
	// list is a filter rather than a copy because the settings also hold the
	// relay's private key material.
	for _, key := range []string{"psk", "uuid", "password", "method", "username", "network", "path", "flow", "fingerprint"} {
		if v, ok := l.Settings[key]; ok {
			creds[key] = fmt.Sprint(v)
		}
	}

	if l.Transport == "reality" {
		// The public key is not stored, so it is recomputed. A failure here is
		// reported as an empty value rather than an error: the rest of the
		// credentials are still valid, and refusing to print anything would
		// hide a working relay behind one broken field.
		if priv := stringSetting(l.Settings, "privateKey"); priv != "" {
			if pub, err := reality.PublicKeyFromPrivate(priv); err == nil {
				creds["publicKey"] = pub
			}
		}
		if v, ok := l.Settings["shortId"]; ok {
			creds["shortId"] = fmt.Sprint(v)
		}
		// serverNames is a list on the relay but a single name on the client.
		if names := stringSliceSetting(l.Settings, "serverNames"); len(names) > 0 {
			creds["serverName"] = names[0]
		} else if v := stringSetting(l.Settings, "serverName"); v != "" {
			creds["serverName"] = v
		}
	}
	return creds
}

func stringSetting(s map[string]any, key string) string {
	if s == nil {
		return ""
	}
	v, ok := s[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

// stringSliceSetting reads a settings value that may be a []string or a
// []any, which is what a JSON round-trip produces.
func stringSliceSetting(s map[string]any, key string) []string {
	if s == nil {
		return nil
	}
	switch v := s[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
		return out
	}
	return nil
}

// DeployOptions parameterises a remote deployment.
type DeployOptions struct {
	Host           string
	Port           int
	Username       string
	AuthMethod     string
	PrivateKeyPath string
	Password       string
	Transport      string
	RelayPort      int
	Name           string
	// LocalBinaryPath overrides the binary that is uploaded. Empty means "this
	// executable", which is then checked against the target platform.
	LocalBinaryPath string
	// DownloadURL is used when no uploadable binary for the target platform is
	// available. {os} and {arch} are substituted.
	DownloadURL string
	AddToConfig string
}

// DeployRemote installs a relay on another host over SSH.
func DeployRemote(opts DeployOptions) error {
	// The implementation lives in the sshdeploy package so the management
	// console and the CLI share exactly one code path.
	return deployRemoteImpl(opts)
}

// systemctl runs a systemctl subcommand, surfacing its output on failure.
func systemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}

// copyFile copies src to dst with the given mode.
//
// It writes to a temporary file and renames, so a failed or interrupted copy
// never leaves a half-written executable at the destination path.
func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Chmod(dst, mode)
}
