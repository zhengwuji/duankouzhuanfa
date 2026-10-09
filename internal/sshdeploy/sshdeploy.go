// Package sshdeploy installs a PortTransit relay on a remote host over SSH.
//
// # Why SSH rather than an agent
//
// The alternative design is to run a small installer agent on the relay and
// have the client drive it over HTTP. That would mean the relay host listens on
// an extra port before it is configured, which is exactly the window in which a
// fresh server is most likely to be scanned. SSH is already there, already
// authenticated, already firewalled, and already the thing the operator used to
// get the machine — so driving the install over it adds no new exposure.
//
// # What an install does
//
//  1. Detect the distribution and architecture.
//  2. Upload the relay binary (or download it if the host has egress).
//  3. Write a configuration with a generated credential.
//  4. Install and start a systemd unit.
//  5. Report the connection details back to the client so it can add the relay
//     in one step.
package sshdeploy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Request parameterises one deployment.
type Request struct {
	// Host is the remote address, without a port.
	Host string
	// Port is the SSH port. Zero means 22.
	Port int
	// Username is the SSH account. It must be able to use sudo.
	Username string
	// Password authenticates when AuthMethod is "password".
	Password string
	// PrivateKeyPath is a file holding a PEM private key. When empty and
	// AuthMethod is "key", the standard agent and key locations are tried.
	PrivateKeyPath string
	// PrivateKeyPEM is an inline private key, used when the caller has the
	// key material but no file. It takes precedence over PrivateKeyPath.
	PrivateKeyPEM []byte
	// AuthMethod is "key" or "password".
	AuthMethod string
	// HostKeyCallback verifies the remote host key. When nil, the standard
	// known_hosts file is used, and an unknown host is refused rather than
	// trusted — silently trusting a first connection is how a deployment ends
	// up shipping a credential to an attacker.
	HostKeyCallback ssh.HostKeyCallback

	// Transport is the relay transport to configure.
	Transport string
	// RelayPort is the port the relay listens on.
	RelayPort int
	// Name is a label for the new relay.
	Name string

	// LocalBinaryPath is a prebuilt relay binary to upload. When empty the
	// remote host downloads a release instead.
	LocalBinaryPath string
	// DownloadURL is where the remote host fetches the binary when
	// LocalBinaryPath is empty.
	DownloadURL string

	// Timeout bounds the whole deployment.
	Timeout time.Duration
	// Log receives a line-by-line transcript.
	Log func(string)
}

// Result reports the outcome.
type Result struct {
	OK bool `json:"ok"`
	// Error is the failure reason when OK is false.
	Error string `json:"error,omitempty"`
	// Log is the full transcript.
	Log []string `json:"log,omitempty"`
	// Summary is a one-line success description.
	Summary string `json:"summary,omitempty"`

	// The fields below let the client add the relay without the operator
	// copying anything by hand.
	Address   string            `json:"address,omitempty"`
	Transport string            `json:"transport,omitempty"`
	Port      int               `json:"port,omitempty"`
	Settings  map[string]string `json:"settings,omitempty"`
	ClientID  string            `json:"clientId,omitempty"`
}

// Remote paths the installer creates.
const (
	remoteBinPath    = "/usr/local/bin/porttransit"
	remoteConfigDir  = "/etc/porttransit"
	remoteConfigPath = "/etc/porttransit/config.json"
	remoteUnitPath   = "/etc/systemd/system/porttransit.service"
	remoteDataDir    = "/var/lib/porttransit"
	remoteLogDir     = "/var/log/porttransit"
	remoteTmpBin     = "/tmp/porttransit.upload"
)

// DefaultTimeout bounds a deployment.
const DefaultTimeout = 5 * time.Minute

// Deploy runs a full installation.
//
// Every step is idempotent: re-running against a host that already has a relay
// upgrades the binary and rewrites the unit, which is what makes "deploy"
// double as "repair".
func Deploy(ctx context.Context, req Request) *Result {
	if req.Timeout <= 0 {
		req.Timeout = DefaultTimeout
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.Username == "" {
		req.Username = "root"
	}
	if req.RelayPort == 0 {
		req.RelayPort = 8443
	}
	if req.Transport == "" {
		req.Transport = "tls"
	}

	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	res := &Result{Transport: req.Transport, Port: req.RelayPort}
	emit := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		res.Log = append(res.Log, line)
		if req.Log != nil {
			req.Log(line)
		}
	}
	fail := func(format string, args ...any) *Result {
		msg := fmt.Sprintf(format, args...)
		emit("错误：%s", msg)
		res.OK = false
		res.Error = msg
		return res
	}

	if req.Host == "" {
		return fail("必须提供服务器地址")
	}

	emit("正在连接 %s:%d（用户 %s）…", req.Host, req.Port, req.Username)
	client, err := dial(ctx, req, emit)
	if err != nil {
		return fail("SSH 连接失败：%v", err)
	}
	defer client.Close()
	emit("SSH 连接成功")

	// Step 1: identify the host so the installer can refuse an unsupported
	// distribution before changing anything on it.
	emit("检测远程系统…")
	info, err := detectSystem(ctx, client)
	if err != nil {
		return fail("无法识别远程系统：%v", err)
	}
	emit("系统：%s %s（%s）", info.PrettyName, info.VersionID, info.Arch)
	if !info.Supported {
		return fail("不支持的发行版 %q，仅支持 Debian 与 Ubuntu", info.ID)
	}
	if info.Arch != "amd64" && info.Arch != "arm64" {
		return fail("不支持的架构 %q，仅支持 amd64 与 arm64", info.Arch)
	}

	// Step 2: obtain a binary that actually runs on the remote host.
	//
	// Uploading a local build is preferred because it guarantees the relay runs
	// the same version as the client, which is what makes the generated
	// configuration match. But "the local build" is only correct when it was
	// built for the target: a Windows client deploying to a Linux server would
	// otherwise install a PE image that the remote kernel rejects with
	// "Exec format error" — and the failure surfaces as an opaque unit-start
	// error long after the upload looked successful.
	//
	// So the local binary's header is checked first, and anything that cannot
	// run on linux/<arch> is replaced by a matching build found beside it, or
	// by a download. Refusing is better than uploading something that cannot
	// execute, because a half-installed relay that never starts is the worst
	// outcome to debug.
	uploadPath := req.LocalBinaryPath
	uploadFrom := ""
	if uploadPath != "" {
		local, err := InspectBinary(uploadPath)
		if err != nil {
			emit("警告：无法读取本地程序头部（%v），将按原样上传", err)
		} else if !local.UsableOn("linux", info.Arch) {
			emit("本地程序是 %s，无法在 linux/%s 上运行，正在查找匹配的构建…", local, info.Arch)
			found, hint := FindCompatibleBinary(uploadPath, "linux", info.Arch)
			if found != "" {
				uploadPath = found
				uploadFrom = fmt.Sprintf("（本地程序为 %s，改用 %s）", local, found)
			} else {
				uploadPath = ""
				if hint != "" {
					emit("未找到匹配的构建，已查找：%s", hint)
				}
			}
		}
	}

	switch {
	case uploadPath != "":
		emit("上传服务端程序%s…", uploadFrom)
		if err := uploadFile(ctx, client, uploadPath, remoteTmpBin, 0o755); err != nil {
			return fail("上传失败：%v", err)
		}
	case req.DownloadURL != "":
		url := ExpandDownloadURL(req.DownloadURL, "linux", info.Arch)
		emit("在服务器上下载服务端程序…")
		if _, err := runSudo(ctx, client, req.Username,
			fmt.Sprintf("curl -fsSL %s -o %s && chmod 0755 %s",
				shellQuote(url), remoteTmpBin, remoteTmpBin)); err != nil {
			return fail("下载失败：%v", err)
		}
	default:
		if req.LocalBinaryPath != "" {
			return fail("本地程序不能在 linux/%s 上运行，且旁边没有匹配的构建，也没有配置下载地址。\n"+
				"请下载 linux/%s 的发行版，与本地程序放在同一目录（文件名形如 porttransit-linux-%s），\n"+
				"或指定下载地址（支持 {os}/{arch} 占位符）。",
				info.Arch, info.Arch, info.Arch)
		}
		return fail("既没有本地二进制也没有下载地址，无法安装")
	}

	// Step 3: install the binary and create the directories.
	emit("安装程序到 %s…", remoteBinPath)
	if _, err := runSudo(ctx, client, req.Username, strings.Join([]string{
		"install -m 0755 " + remoteTmpBin + " " + remoteBinPath,
		"rm -f " + remoteTmpBin,
		"mkdir -p " + remoteConfigDir + " " + remoteDataDir + " " + remoteLogDir,
		"chmod 0750 " + remoteConfigDir,
	}, " && ")); err != nil {
		return fail("安装失败：%v", err)
	}

	// Prove the installed program actually executes before configuring it.
	// Without this, a binary built for the wrong platform fails later with a
	// bare "Exec format error" from an unrelated step, which reads like a
	// configuration problem rather than an architecture mismatch.
	if out, err := runSudo(ctx, client, req.Username, remoteBinPath+" version"); err != nil {
		detail := strings.TrimSpace(out)
		if detail != "" {
			return fail("安装的程序无法执行（%v）：%s\n这通常说明上传的二进制不是 linux/%s 构建。", err, detail, info.Arch)
		}
		return fail("安装的程序无法执行：%v\n这通常说明上传的二进制不是 linux/%s 构建。", err, info.Arch)
	}

	// Step 4: generate the relay configuration on the remote host, using the
	// relay binary itself so the credential format is produced by the same
	// code that will consume it.
	emit("生成中转配置…")
	if _, err := runSudo(ctx, client, req.Username, strings.Join([]string{
		remoteBinPath + " init --mode server --force",
		"--config " + remoteConfigPath,
		"--listen 0.0.0.0:" + strconv.Itoa(req.RelayPort),
		"--transport " + shellQuote(req.Transport),
		"--name " + shellQuote(defaultName(req.Name, req.Host)),
		"--print-credentials",
	}, " ")); err != nil {
		return fail("生成配置失败：%v", err)
	}

	// The config holds the relay PSK and the console password hash. `init`
	// writes it 0600, but a re-run over a file created by some other path (or
	// an older version) could leave it readable, and the service runs as root —
	// so enforce the mode here rather than trusting whatever is on disk.
	if _, err := runSudo(ctx, client, req.Username, "chmod 0600 "+remoteConfigPath); err != nil {
		return fail("设置配置权限失败：%v", err)
	}

	// Read back the generated credentials so the client can add the relay
	// immediately.
	creds, err := readCredentials(ctx, client, req.Username)
	if err != nil {
		emit("警告：未能读取生成的凭据，请在服务器上手动查看 %s", remoteConfigPath)
	}

	// Step 5: install the service unit.
	emit("安装 systemd 服务…")
	if err := installUnit(ctx, client, req.Username); err != nil {
		return fail("安装服务失败：%v", err)
	}

	emit("启动服务…")
	if _, err := runSudo(ctx, client, req.Username,
		"systemctl daemon-reload && systemctl enable --now porttransit && sleep 1 && systemctl is-active porttransit"); err != nil {
		// A failed start is worth diagnosing rather than just reporting, so the
		// unit's own log tail is fetched and shown.
		if out, logErr := runSudo(ctx, client, req.Username, "journalctl -u porttransit -n 20 --no-pager"); logErr == nil {
			emit("服务日志：\n%s", out)
		}
		return fail("服务启动失败：%v", err)
	}
	emit("服务已启动")

	// Step 6: verify the relay is actually listening, and open the firewall if
	// one is active.
	emit("检查监听端口 %d…", req.RelayPort)
	if out, err := runSudo(ctx, client, req.Username,
		fmt.Sprintf("ss -lntp 2>/dev/null | grep -c ':%d ' || true", req.RelayPort)); err == nil {
		if strings.TrimSpace(out) == "0" {
			emit("警告：未检测到端口 %d 处于监听状态", req.RelayPort)
		} else {
			emit("端口 %d 正在监听", req.RelayPort)
		}
	}

	emit("检查防火墙…")
	openFirewall(ctx, client, req.Username, req.RelayPort, emit)

	res.OK = true
	res.Address = net.JoinHostPort(req.Host, strconv.Itoa(req.RelayPort))
	res.Settings = creds
	res.Summary = fmt.Sprintf("%s 已安装 %s 中转服务端，监听 %s", req.Host, req.Transport, res.Address)
	emit("完成：%s", res.Summary)
	return res
}

// systemInfo describes the remote host.
type systemInfo struct {
	ID         string
	VersionID  string
	PrettyName string
	Arch       string
	Supported  bool
}

// detectSystem reads /etc/os-release.
func detectSystem(ctx context.Context, client *ssh.Client) (*systemInfo, error) {
	out, err := run(ctx, client, ". /etc/os-release 2>/dev/null; echo \"$ID|$VERSION_ID|$PRETTY_NAME\"")
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(out), "|")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unexpected os-release output %q", out)
	}
	info := &systemInfo{ID: parts[0], VersionID: parts[1], PrettyName: parts[2]}
	info.Supported = info.ID == "debian" || info.ID == "ubuntu" || strings.HasPrefix(info.ID, "ubuntu")

	arch, err := run(ctx, client, "uname -m")
	if err != nil {
		return nil, err
	}
	switch strings.TrimSpace(arch) {
	case "x86_64", "amd64":
		info.Arch = "amd64"
	case "aarch64", "arm64":
		info.Arch = "arm64"
	default:
		info.Arch = strings.TrimSpace(arch)
	}
	return info, nil
}

// readCredentials pulls the generated relay settings back off the host.
func readCredentials(ctx context.Context, client *ssh.Client, username string) (map[string]string, error) {
	out, err := runSudo(ctx, client, username, remoteBinPath+" show-credentials --config "+remoteConfigPath+" --json")
	if err != nil {
		return nil, err
	}
	creds := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// The helper prints one key=value per line, which avoids requiring a
		// JSON parser on a host that may not have one.
		if k, v, ok := strings.Cut(line, "="); ok {
			creds[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if len(creds) == 0 {
		return nil, errors.New("no credentials were reported")
	}
	return creds, nil
}

// installUnit writes and enables the systemd unit.
func installUnit(ctx context.Context, client *ssh.Client, username string) error {
	unit := `[Unit]
Description=PortTransit relay
Documentation=https://github.com/zhengwuji/duankouzhuanfa
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=` + remoteBinPath + ` run --config ` + remoteConfigPath + `
Restart=always
RestartSec=3
LimitNOFILE=1048576
# The relay needs no privileges beyond binding its port. When that port is
# above 1024 it can drop to an unprivileged account entirely.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=` + remoteDataDir + ` ` + remoteLogDir + ` ` + remoteConfigDir + `
StandardOutput=append:` + remoteLogDir + `/porttransit.log
StandardError=append:` + remoteLogDir + `/porttransit.log

[Install]
WantedBy=multi-user.target
`
	if err := runSudoInput(ctx, client, username, unit, "tee "+remoteUnitPath+" > /dev/null && chmod 0644 "+remoteUnitPath); err != nil {
		return err
	}
	return nil
}

// openFirewall opens the relay port if a firewall is active.
//
// A relay that installs cleanly but is unreachable because of ufw is the most
// common support question, so the installer checks rather than leaving the
// operator to discover it.
func openFirewall(ctx context.Context, client *ssh.Client, username string, port int, emit func(string, ...any)) {
	if out, err := runSudo(ctx, client, username, "command -v ufw >/dev/null && ufw status | head -1"); err == nil {
		if strings.Contains(strings.ToLower(out), "active") {
			cmd := fmt.Sprintf("ufw allow %d/tcp", port)
			if _, err := runSudo(ctx, client, username, cmd); err != nil {
				emit("警告：ufw 放行失败：%v", err)
			} else {
				emit("已在 ufw 中放行 %d/tcp", port)
			}
		}
	}
	if out, err := runSudo(ctx, client, username, "command -v firewall-cmd >/dev/null && firewall-cmd --state"); err == nil {
		if strings.Contains(strings.ToLower(out), "running") {
			cmd := fmt.Sprintf("firewall-cmd --permanent --add-port=%d/tcp && firewall-cmd --reload", port)
			if _, err := runSudo(ctx, client, username, cmd); err != nil {
				emit("警告：firewalld 放行失败：%v", err)
			} else {
				emit("已在 firewalld 中放行 %d/tcp", port)
			}
		}
	}
	if out, err := runSudo(ctx, client, username, "command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | head -5"); err == nil {
		// Only report; adding raw iptables rules without knowing the host's
		// policy could lock the operator out, which is far worse than a closed
		// port they can open themselves.
		if strings.Contains(out, "DROP") || strings.Contains(out, "REJECT") {
			emit("提示：检测到 iptables 存在 DROP/REJECT 规则，若无法连接请手动放行 %d/tcp", port)
		}
	}
}

// dial establishes the SSH connection.
func dial(ctx context.Context, req Request, emit func(string, ...any)) (*ssh.Client, error) {
	auths, err := authMethods(req)
	if err != nil {
		return nil, err
	}

	callback := req.HostKeyCallback
	if callback == nil {
		callback, err = defaultHostKeyCallback(emit)
		if err != nil {
			return nil, err
		}
	}

	cfg := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            auths,
		HostKeyCallback: callback,
		Timeout:         20 * time.Second,
	}

	addr := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	dialer := net.Dialer{Timeout: 20 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// The SSH handshake is bounded separately from the TCP connect, because a
	// host that accepts a connection and then stalls is a real failure mode.
	type result struct {
		client *ssh.Client
		err    error
	}
	done := make(chan result, 1)
	go func() {
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			done <- result{err: err}
			return
		}
		done <- result{client: ssh.NewClient(c, chans, reqs)}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			conn.Close()
			return nil, r.err
		}
		return r.client, nil
	case <-ctx.Done():
		conn.Close()
		return nil, ctx.Err()
	case <-time.After(30 * time.Second):
		conn.Close()
		return nil, errors.New("SSH handshake timed out")
	}
}

// authMethods builds the authentication chain.
func authMethods(req Request) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if len(req.PrivateKeyPEM) > 0 {
		signer, err := ssh.ParsePrivateKey(req.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if req.PrivateKeyPath != "" {
		pem, err := os.ReadFile(req.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key %s: %w", req.PrivateKeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			return nil, fmt.Errorf("parse private key %s: %w", req.PrivateKeyPath, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	// When no explicit key is given, fall back to the agent and the standard
	// key files, which is what an operator already has configured.
	if req.AuthMethod != "password" && len(methods) == 0 {
		if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
			if agentSigners, err := agentAuth(sock); err == nil {
				methods = append(methods, ssh.PublicKeys(agentSigners...))
			}
		}
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			p := path.Join(homeDir(), ".ssh", name)
			pem, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			signer, err := ssh.ParsePrivateKey(pem)
			if err != nil {
				continue
			}
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}

	if req.Password != "" {
		methods = append(methods,
			ssh.Password(req.Password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				// Some hardened hosts route password auth through the
				// keyboard-interactive method; answering the prompt keeps a
				// password deployment working there.
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = req.Password
				}
				return answers, nil
			}),
		)
	}

	if len(methods) == 0 {
		return nil, errors.New("no SSH authentication method is available: provide a key, a password, or start ssh-agent")
	}
	return methods, nil
}

// defaultHostKeyCallback verifies the host key against known_hosts.
func defaultHostKeyCallback(emit func(string, ...any)) (ssh.HostKeyCallback, error) {
	khPath := path.Join(homeDir(), ".ssh", "known_hosts")
	cb, err := knownhosts.New(khPath)
	if err != nil {
		// Without a known_hosts file there is nothing to verify against, and
		// silently accepting any key would make the deployment a credential
		// handover to whoever answers on that address.
		return nil, fmt.Errorf("cannot verify the server's SSH host key: %w (create %s by connecting once with ssh)", err, khPath)
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := cb(hostname, remote, key); err != nil {
			return fmt.Errorf("the server's SSH host key is not trusted: %w", err)
		}
		return nil
	}, nil
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return h
	}
	return "."
}

// run executes a command without sudo.
func run(ctx context.Context, client *ssh.Client, cmd string) (string, error) {
	return runWithInput(ctx, client, cmd, nil)
}

// runSudo executes a command, escalating through sudo when the account is not
// already root.
func runSudo(ctx context.Context, client *ssh.Client, username, cmd string) (string, error) {
	if username == "root" {
		return run(ctx, client, cmd)
	}
	// sudo -n first: if passwordless sudo is configured the command runs
	// without a prompt, and if it is not, the failure is immediate and legible
	// rather than hanging on a prompt nobody can answer.
	wrapped := "sudo -n sh -c " + shellQuote(cmd)
	out, err := run(ctx, client, wrapped)
	if err != nil && strings.Contains(out, "password") {
		return "", fmt.Errorf("this account needs a password for sudo, but the deployment cannot answer a prompt; configure passwordless sudo or use root: %w", err)
	}
	return out, err
}

// runSudoInput runs a command as root with stdin supplied.
func runSudoInput(ctx context.Context, client *ssh.Client, username, input, cmd string) error {
	if username != "root" {
		cmd = "sudo -n sh -c " + shellQuote(cmd)
	}
	_, err := runWithInput(ctx, client, cmd, []byte(input))
	return err
}

// runWithInput opens a session, optionally writes stdin, and returns stdout.
func runWithInput(ctx context.Context, client *ssh.Client, cmd string, input []byte) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if input != nil {
		stdin, err := session.StdinPipe()
		if err != nil {
			return "", err
		}
		go func() {
			defer stdin.Close()
			_, _ = stdin.Write(input)
		}()
	}

	done := make(chan error, 1)
	if err := session.Start(cmd); err != nil {
		return "", err
	}
	go func() { done <- session.Wait() }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return stdout.String(), ctx.Err()
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = strings.TrimSpace(stdout.String())
			}
			return stdout.String(), fmt.Errorf("%v: %s", err, truncate(msg, 400))
		}
		return stdout.String(), nil
	}
}

// uploadFile streams a local file to a remote path.
//
// It pipes through `cat` rather than using the SFTP subsystem, because a
// minimal server image may not have the subsystem enabled and `cat` always
// exists.
func uploadFile(ctx context.Context, client *ssh.Client, localPath, remotePath string, mode os.FileMode) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	session.Stderr = &stderr

	if err := session.Start(fmt.Sprintf("cat > %s && chmod %04o %s", shellQuote(remotePath), mode, shellQuote(remotePath))); err != nil {
		return err
	}

	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(stdin, f)
		cerr := stdin.Close()
		if err == nil {
			err = cerr
		}
		copyDone <- err
	}()

	waitDone := make(chan error, 1)
	go func() { waitDone <- session.Wait() }()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return ctx.Err()
	case err := <-copyDone:
		if err != nil {
			return err
		}
	case <-time.After(3 * time.Minute):
		_ = session.Signal(ssh.SIGKILL)
		return errors.New("upload timed out")
	}

	select {
	case err := <-waitDone:
		if err != nil {
			return fmt.Errorf("remote write failed: %v: %s", err, truncate(strings.TrimSpace(stderr.String()), 300))
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// shellQuote wraps a string for safe use in a remote shell.
//
// Single quotes with internal quote escaping is the only form that is safe
// against every metacharacter, which matters because these strings include
// operator-supplied values such as a transport name.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func defaultName(name, host string) string {
	if name != "" {
		return name
	}
	return "中转-" + host
}
