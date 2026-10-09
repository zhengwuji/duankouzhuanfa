// Package app wires the configuration, the logger, the relay, the client and
// the management interface into one runnable process.
//
// It exists so that the CLI and the installer script share exactly one startup
// path: the same defaults, the same validation, the same shutdown ordering.
// Anything that both a `porttransit server` invocation and a systemd unit need
// to do belongs here rather than in main.
package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"porttransit/internal/client"
	"porttransit/internal/config"
	"porttransit/internal/logx"
	"porttransit/internal/server"
	"porttransit/internal/version"
	"porttransit/internal/webui"

	// Register every transport for its side effect. Importing the aggregate
	// package here means the CLI never has to know which schemes exist.
	_ "porttransit/internal/transports"
)

// DefaultPaths are the conventional locations the installer creates.
const (
	DefaultConfigPath = "/etc/porttransit/config.json"
	DefaultDataDir    = "/var/lib/porttransit"
	DefaultLogPath    = "/var/log/porttransit/porttransit.log"
	DefaultStateDir   = "/var/lib/porttransit"
)

// App is a wired-up PortTransit process.
type App struct {
	cfgPath string
	cfg     *config.Config
	log     *logx.Logger
	buffer  *logx.Buffer

	server *server.Server
	client *client.Client
	webui  *webui.Server

	mu      sync.Mutex
	stopped bool
}

// Options parameterises New.
type Options struct {
	// ConfigPath is the JSON configuration to load. Required.
	ConfigPath string
	// ModeOverride forces a role, ignoring config.Mode. Empty keeps the
	// configured mode.
	ModeOverride config.Mode
	// LogLevel overrides the configured level.
	LogLevel string
	// LogFile overrides the configured log file. "-" forces stderr.
	LogFile string
	// NoWebUI disables the management interface regardless of configuration.
	NoWebUI bool
}

// New loads the configuration and constructs the logger and subsystems. It
// does not bind any socket; call Run for that.
func New(opts Options) (*App, error) {
	if opts.ConfigPath == "" {
		return nil, errors.New("app: a configuration path is required")
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		// A missing config is the expected state on a first run, so it is
		// reported with the command that fixes it rather than as a bare error.
		//
		// errors.Is is required here rather than os.IsNotExist: config.Load
		// wraps the read error with %w, and os.IsNotExist deliberately does not
		// unwrap, so it would never match and the operator would see only the
		// raw path error.
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w (create one with: porttransit init --config %s)", err, opts.ConfigPath)
		}
		return nil, err
	}
	if opts.ModeOverride != "" {
		cfg.Mode = opts.ModeOverride
	}
	if opts.LogLevel != "" {
		cfg.Log.Level = opts.LogLevel
	}
	if opts.LogFile != "" {
		if opts.LogFile == "-" {
			cfg.Log.File = ""
		} else {
			cfg.Log.File = opts.LogFile
		}
	}
	if opts.NoWebUI {
		cfg.WebUI.Enabled = false
	}

	// Re-validate after the overrides, because an override can create an
	// invalid combination that the file alone did not have.
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	a := &App{cfgPath: opts.ConfigPath, cfg: cfg}

	log, buf, err := buildLogger(cfg)
	if err != nil {
		return nil, err
	}
	a.log = log
	a.buffer = buf

	if (cfg.Mode == config.ModeServer || cfg.Mode == config.ModeBoth) && cfg.Server != nil {
		srv, err := server.New(cfg.Server, a.log)
		if err != nil {
			return nil, err
		}
		a.server = srv
	}
	if (cfg.Mode == config.ModeClient || cfg.Mode == config.ModeBoth) && cfg.Client != nil {
		cli, err := client.New(cfg.Client, a.log)
		if err != nil {
			return nil, err
		}
		a.client = cli
	}

	if cfg.WebUI.Enabled {
		ui, err := webui.New(webui.Options{
			Config: cfg,
			Path:   opts.ConfigPath,
			Logger: a.log,
			Buffer: buf,
			Server: a.server,
			Client: a.client,
		})
		if err != nil {
			return nil, err
		}
		a.webui = ui
	}
	return a, nil
}

// buildLogger constructs the shared logger and its in-memory ring.
func buildLogger(cfg *config.Config) (*logx.Logger, *logx.Buffer, error) {
	size := cfg.Log.BufferSize
	if size <= 0 {
		size = 1000
	}
	buf := logx.NewBuffer(size)

	file := cfg.Log.File
	if file == "" && cfg.Mode == config.ModeServer {
		// A relay installed as a service has no console, so defaulting to a
		// file is what makes its logs recoverable after the fact.
		file = DefaultLogPath
	}
	if file != "" {
		if err := os.MkdirAll(filepath.Dir(file), 0o750); err != nil {
			return nil, nil, fmt.Errorf("app: create log directory: %w", err)
		}
	}

	log, err := logx.New(logx.Options{
		Level:     logx.ParseLevel(cfg.Log.Level),
		Component: "porttransit",
		File:      file,
		JSON:      cfg.Log.JSON,
		Buffer:    buf,
		Console:   true,
	})
	if err != nil {
		return nil, nil, err
	}
	return log, buf, nil
}

// Run starts every subsystem and blocks until the context is cancelled or a
// termination signal arrives.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	a.log.Info("PortTransit starting",
		"version", version.Short(),
		"build", version.BuildStamp(),
		"mode", string(a.cfg.Mode),
		"config", a.cfgPath,
	)

	if a.server != nil {
		if err := a.server.Start(ctx); err != nil {
			return err
		}
	}
	if a.client != nil {
		if err := a.client.Start(ctx); err != nil {
			// The relay is already bound; leaving it running would report a
			// success that is only half true.
			if a.server != nil {
				a.server.Stop()
			}
			return err
		}
	}
	if a.webui != nil {
		if err := a.webui.Start(ctx); err != nil {
			if a.client != nil {
				a.client.Stop()
			}
			if a.server != nil {
				a.server.Stop()
			}
			return err
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
		a.log.Info("shutdown requested")
	case sig := <-sigCh:
		a.log.Info("signal received, shutting down", "signal", sig.String())
	}

	a.Stop()
	return nil
}

// Stop shuts every subsystem down in reverse start order.
//
// The management interface goes first so no new request can be accepted while
// the relay is tearing down, and the client goes before the relay because a
// client that is still tunnelling through a stopping relay produces a burst of
// spurious failures.
func (a *App) Stop() {
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	a.stopped = true
	a.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if a.webui != nil {
			a.webui.Stop()
		}
		if a.client != nil {
			a.client.Stop()
		}
		if a.server != nil {
			a.server.Stop()
		}
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		if a.log != nil {
			a.log.Warn("shutdown timed out; some connections were abandoned")
		}
	}

	// The log file is released last so the shutdown messages above are still
	// recorded. A service manager that rotates the log needs the handle gone.
	if a.log != nil {
		_ = a.log.Close()
	}
}

// Config returns the loaded configuration.
func (a *App) Config() *config.Config { return a.cfg }

// Server returns the relay, or nil when the mode excludes it.
func (a *App) Server() *server.Server { return a.server }

// Client returns the client, or nil when the mode excludes it.
func (a *App) Client() *client.Client { return a.client }

// WebUI returns the management interface, or nil when it is disabled.
func (a *App) WebUI() *webui.Server { return a.webui }

// Logger returns the shared logger.
func (a *App) Logger() *logx.Logger { return a.log }
