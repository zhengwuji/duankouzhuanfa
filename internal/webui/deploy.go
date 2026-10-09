package webui

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"porttransit/internal/config"
	"porttransit/internal/sshdeploy"
)

// Remote relay deployment.
//
// This is the "install the relay on my server" button. It drives the same
// installer the command line uses, over the SSH connection the operator
// already has, and on success writes the new relay straight into the client
// configuration so there is nothing to copy by hand.
//
// # Why the transcript is returned in full
//
// An install touches a remote machine the operator cannot see. Returning only
// a pass/fail would leave them with no way to tell a missing sudo from a
// blocked port, so the whole transcript is sent back and rendered verbatim.

// deployJob tracks one in-flight deployment so its progress can be polled.
type deployJob struct {
	ID      string   `json:"id"`
	Host    string   `json:"host"`
	Started string   `json:"started"`
	Lines   []string `json:"lines"`
	Done    bool     `json:"done"`
	OK      bool     `json:"ok"`
	Error   string   `json:"error,omitempty"`
	Summary string   `json:"summary,omitempty"`
	Address string   `json:"address,omitempty"`
	Added   string   `json:"addedServerId,omitempty"`

	mu sync.Mutex
}

func (j *deployJob) append(line string) {
	j.mu.Lock()
	j.Lines = append(j.Lines, line)
	j.mu.Unlock()
}

func (j *deployJob) snapshot() map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	lines := make([]string, len(j.Lines))
	copy(lines, j.Lines)
	return map[string]any{
		"id":            j.ID,
		"host":          j.Host,
		"started":       j.Started,
		"lines":         lines,
		"done":          j.Done,
		"ok":            j.OK,
		"error":         j.Error,
		"summary":       j.Summary,
		"address":       j.Address,
		"addedServerId": j.Added,
	}
}

// deployRequest is the API's view of a deployment.
type deployRequest struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Username       string `json:"username"`
	AuthMethod     string `json:"authMethod"`
	PrivateKeyPath string `json:"privateKeyPath"`
	Password       string `json:"password"`
	Transport      string `json:"transport"`
	RelayPort      int    `json:"relayPort"`
	Name           string `json:"name"`
	// DownloadURL is where the remote host fetches the relay binary. It is only
	// used when the running console cannot supply a binary for the target
	// platform — which is the normal case when this console runs on Windows and
	// the relay is a Linux server. {os} and {arch} are substituted.
	DownloadURL string `json:"downloadUrl,omitempty"`
	// AddToClient controls whether the new relay is written into the client
	// configuration on success.
	AddToClient *bool `json:"addToClient,omitempty"`
}

// handleDeploy runs a deployment synchronously and returns the transcript.
//
// It is synchronous because a deployment is interactive: the operator is
// waiting to see whether it worked, and a job id would only add a polling loop
// for no benefit. The timeout bounds the whole call.
func (s *Server) handleDeploy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "deployment requires POST")
		return
	}
	var body deployRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if strings.TrimSpace(body.Host) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "a server address is required")
		return
	}
	if body.AuthMethod == "" {
		body.AuthMethod = "key"
	}
	if err := sshdeploy.CheckKeyFile(body.PrivateKeyPath); err != nil {
		writeError(w, http.StatusBadRequest, "bad_key", "%v", err)
		return
	}

	req := sshdeploy.Request{
		Host:           strings.TrimSpace(body.Host),
		Port:           body.Port,
		Username:       strings.TrimSpace(body.Username),
		AuthMethod:     body.AuthMethod,
		PrivateKeyPath: body.PrivateKeyPath,
		Password:       body.Password,
		Transport:      body.Transport,
		RelayPort:      body.RelayPort,
		Name:           body.Name,
		Timeout:        5 * time.Minute,
	}
	// Prefer uploading this very binary: the relay then runs exactly the
	// version whose credentials and settings the client understands, which is
	// what makes the auto-generated entry correct. Deploy checks the header and
	// falls back to DownloadURL when this binary cannot run on the target, so
	// a Windows console deploying to a Linux relay still works.
	if self, err := os.Executable(); err == nil {
		req.LocalBinaryPath = self
	}
	req.DownloadURL = strings.TrimSpace(body.DownloadURL)

	s.log.Info("relay deployment started",
		"host", req.Host,
		"user", req.Username,
		"transport", req.Transport,
		"port", req.RelayPort,
	)

	res := sshdeploy.Deploy(r.Context(), req)

	// On success, add the relay to the client so the operator does not have to
	// retype an address and a credential that were just generated.
	if res.OK && res.Address != "" && s.cfg.Client != nil {
		addToClient := body.AddToClient == nil || *body.AddToClient
		if addToClient {
			entry := config.ServerEntry{
				ID:         newID("srv"),
				Name:       firstNonEmpty(body.Name, res.Address),
				Address:    res.Address,
				Transport:  res.Transport,
				Enabled:    true,
				Settings:   map[string]any{},
				LatencyTag: body.Host,
			}
			for k, v := range res.Settings {
				entry.Settings[k] = v
			}
			if err := s.mutate(func(cfg *config.Config) error {
				cfg.Client.Servers = append(cfg.Client.Servers, entry)
				return nil
			}); err != nil {
				res.Log = append(res.Log, "警告：服务端已安装，但写入客户端配置失败："+err.Error())
				s.log.Warn("deployed relay could not be added to the client config", "err", err)
			} else {
				res.Log = append(res.Log, "已自动添加中转服务器："+entry.Name)
				s.log.Info("deployed relay added to the client config", "id", entry.ID, "address", entry.Address)
			}
		}
	}

	s.log.Info("relay deployment finished", "host", req.Host, "ok", res.OK, "error", res.Error)
	writeJSON(w, http.StatusOK, res)
}

// handleDeployByID serves the per-job endpoints.
//
// Deployments are currently synchronous, so this only reports that fact
// clearly rather than 404ing, which would look like a bug in the console.
func (s *Server) handleDeployByID(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, "not_supported",
		"deployments run synchronously; poll the POST response instead")
}

// verifyRelay checks a deployed relay's port is reachable from this host.
//
// It is a convenience for the console: a deployment that succeeded on the
// remote host but is unreachable from here is the single most common outcome,
// and finding that out from the console beats finding out from a failed tunnel.
func (s *Server) verifyRelay(host string, port int, timeout time.Duration) (bool, string) {
	addr := host + ":" + strconv.Itoa(port)
	conn, err := dialTimeout(addr, timeout)
	if err != nil {
		return false, err.Error()
	}
	_ = conn.Close()
	return true, ""
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
