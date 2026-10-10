package install

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/bcrypt"

	"porttransit/internal/config"
	"porttransit/internal/sshdeploy"
)

// deployRemoteImpl drives the SSH deployment and optionally records the result
// in a client configuration.
func deployRemoteImpl(opts DeployOptions) error {
	self := opts.LocalBinaryPath
	if self == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate the running executable: %w", err)
		}
		self = exe
	}

	fmt.Printf("==> 正在通过 SSH 部署到 %s\n", opts.Host)

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	res := sshdeploy.Deploy(ctx, sshdeploy.Request{
		Host:            opts.Host,
		Port:            opts.Port,
		Username:        opts.Username,
		AuthMethod:      opts.AuthMethod,
		PrivateKeyPath:  opts.PrivateKeyPath,
		Password:        opts.Password,
		Transport:       opts.Transport,
		RelayPort:       opts.RelayPort,
		Name:            opts.Name,
		LocalBinaryPath: self,
		DownloadURL:     opts.DownloadURL,
		Log:             func(line string) { fmt.Println("   " + line) },
	})

	if !res.OK {
		return fmt.Errorf("部署失败：%s", res.Error)
	}

	fmt.Println()
	fmt.Println("✔ 部署成功")
	fmt.Printf("  地址：%s\n", res.Address)
	fmt.Printf("  协议：%s\n", res.Transport)

	if opts.AddToConfig != "" {
		if err := appendServerToConfig(opts.AddToConfig, res); err != nil {
			fmt.Printf("! 已部署，但写入 %s 失败：%v\n", opts.AddToConfig, err)
			return nil
		}
		fmt.Printf("  已写入客户端配置：%s\n", opts.AddToConfig)
	} else {
		fmt.Println()
		fmt.Println("在客户端添加该中转服务器的参数：")
		fmt.Printf("  porttransit client --config <你的客户端配置>\n")
		fmt.Printf("  或在网页控制台的「中转服务器」中填写：%s\n", res.Address)
		for k, v := range res.Settings {
			fmt.Printf("  %s=%s\n", k, v)
		}
	}
	return nil
}

// appendServerToConfig adds a deployed relay to a client configuration.
func appendServerToConfig(path string, res *sshdeploy.Result) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if cfg.Client == nil {
		return fmt.Errorf("%s 不是客户端配置", path)
	}

	// A relay whose address is already present is replaced rather than
	// duplicated, so re-running a deployment repairs the entry instead of
	// leaving two copies that point at the same host.
	//
	// The settings go through the same translation the "init --mode both" path
	// uses. Copying the relay's reported credentials straight in looks
	// equivalent but is not: a client entry also needs the fields the relay
	// does not have — "insecure" for a freshly generated self-signed
	// certificate, and "tls": false for the schemes the relay serves in the
	// clear. Without them a deployed relay is recorded correctly and then
	// fails every handshake on the user's machine.
	entry := config.ServerEntry{
		ID: "srv-" + shortID(),
		// The listener name is preferred over the address because a host can
		// carry several lines on different ports, and "relay-jp-2" tells the
		// operator more than a second copy of the same IP does.
		Name:      firstNonEmpty(res.Name, res.Settings["name"], res.Address),
		Address:   res.Address,
		Transport: res.Transport,
		Enabled:   true,
		Settings:  ClientSettingsFor(res.Transport, res.Settings),
	}

	for i := range cfg.Client.Servers {
		if cfg.Client.Servers[i].Address == res.Address && cfg.Client.Servers[i].Transport == res.Transport {
			entry.ID = cfg.Client.Servers[i].ID
			cfg.Client.Servers[i] = entry
			return cfg.Save(path)
		}
	}
	cfg.Client.Servers = append(cfg.Client.Servers, entry)
	return cfg.Save(path)
}

// randomPassword returns a URL-safe random password.
func randomPassword() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("install: entropy source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashPassword renders a password as a bcrypt hash.
func hashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// shortID returns a short random identifier suffix.
func shortID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic("install: entropy source failed: " + err.Error())
	}
	return fmt.Sprintf("%x", b)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
