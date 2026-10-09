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
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"porttransit/internal/config"
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
		fmt.Printf("transport=%s\n", l.Transport)
		fmt.Printf("listen=%s\n", l.Listen)
		fmt.Printf("name=%s\n", l.Name)
		for _, key := range []string{"psk", "uuid", "password", "method", "publicKey", "shortId", "serverName", "username", "network", "path", "flow", "fingerprint"} {
			if v, ok := l.Settings[key]; ok {
				fmt.Printf("%s=%v\n", key, v)
			}
		}
		// Only the first enabled listener is reported: a client entry names one
		// endpoint, and an operator adding a second one can read the config.
		return nil
	}
	return errors.New("show-credentials: 没有已启用的中转监听")
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
