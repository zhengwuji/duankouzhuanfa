// Command guitest drives the management console over real HTTP the way a
// browser does: it logs in, exercises the read endpoints, and verifies that a
// configuration read never leaks a secret.
//
// It exists because the console is the only view an operator has of a running
// relay, so "the API answers" is not the same claim as "the API answers
// correctly and safely".
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

func main() {
	var (
		base   = flag.String("url", "http://127.0.0.1:18787", "console base URL")
		user   = flag.String("user", "admin", "console user name")
		pass   = flag.String("password", "", "console password")
		tunnel = flag.Int("tunnel", 19300, "expected tunnel listen port")
	)
	flag.Parse()

	if err := run(*base, *user, *pass, *tunnel); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PASS: the console authenticated, reported state, and leaked no secret")
}

type client struct {
	http *http.Client
	base string
}

func run(base, user, pass string, tunnelPort int) error {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}
	c := &client{
		http: &http.Client{Jar: jar, Timeout: 15 * time.Second},
		base: strings.TrimSuffix(base, "/"),
	}

	// 1. The console must refuse an anonymous request rather than serving the
	//    configuration to anyone who can reach the port.
	status, body, err := c.get("/api/v1/status", false)
	if err != nil {
		return err
	}
	if status != http.StatusUnauthorized {
		return fmt.Errorf("an anonymous request to /api/v1/status returned %d, want 401", status)
	}
	_ = body

	// 2. A wrong password must be refused.
	if err := c.login(user, pass+"-wrong"); err == nil {
		return fmt.Errorf("the console accepted a wrong password")
	}

	// 3. The correct password must establish a session.
	if err := c.login(user, pass); err != nil {
		return err
	}

	// 4. The session must be reported as valid.
	status, body, err = c.get("/api/v1/session", true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("/api/v1/session returned %d, want 200", status)
	}

	// 5. Status must describe the running roles.
	status, body, err = c.get("/api/v1/status", true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("/api/v1/status returned %d, want 200", status)
	}
	var st map[string]any
	if err := json.Unmarshal(body, &st); err != nil {
		return fmt.Errorf("decode /api/v1/status: %w", err)
	}

	// 6. The transport list must classify every scheme, because the console
	//    uses that classification to warn about unencrypted relays.
	_, body, err = c.get("/api/v1/transports", true)
	if err != nil {
		return err
	}
	var trResp struct {
		Transports []map[string]any `json:"transports"`
	}
	if err := json.Unmarshal(body, &trResp); err != nil {
		return fmt.Errorf("decode /api/v1/transports: %w", err)
	}
	transports := trResp.Transports
	if len(transports) == 0 {
		return fmt.Errorf("/api/v1/transports listed no transports")
	}
	for _, t := range transports {
		if _, ok := t["encrypted"]; !ok {
			return fmt.Errorf("transport %v has no encrypted classification", t["name"])
		}
	}
	fmt.Printf("      %d transports listed, all classified\n", len(transports))

	// 7. The configuration view must never contain a live secret. This is the
	//    single most important assertion here: the console is reachable by any
	//    browser on the host, and a secret in the payload is a secret leaked.
	_, body, err = c.get("/api/v1/config", true)
	if err != nil {
		return err
	}
	raw := string(body)
	for _, secret := range []string{"QZrXB9Jge1P8d24DRdQU+iqP9AC/PvOBfwZ+wt2g0lw"} {
		if strings.Contains(raw, secret) {
			return fmt.Errorf("/api/v1/config exposed a live secret")
		}
	}
	var cfgView map[string]any
	if err := json.Unmarshal(body, &cfgView); err != nil {
		return fmt.Errorf("decode /api/v1/config: %w", err)
	}
	if !strings.Contains(raw, "__redacted__") {
		return fmt.Errorf("/api/v1/config redacted nothing, which suggests the view is not the redacted one")
	}

	// 8. Health must report the configured relay.
	_, body, err = c.get("/api/v1/health", true)
	if err != nil {
		return err
	}
	var healthResp struct {
		Servers []map[string]any `json:"servers"`
	}
	if err := json.Unmarshal(body, &healthResp); err != nil {
		return fmt.Errorf("decode /api/v1/health: %w", err)
	}
	health := healthResp.Servers
	if len(health) == 0 {
		return fmt.Errorf("/api/v1/health reported no relays")
	}
	fmt.Printf("      health: %v\n", health[0]["name"])

	// 9. Logs must be retrievable, since that is how an operator debugs a relay
	//    they cannot log into directly.
	_, body, err = c.get("/api/v1/logs?limit=50", true)
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("/api/v1/logs returned nothing")
	}

	// 10. The console must serve its own front end.
	resp, err := c.http.Get(c.base + "/")
	if err != nil {
		return fmt.Errorf("fetch the console page: %w", err)
	}
	defer resp.Body.Close()
	page, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the console page returned %d", resp.StatusCode)
	}
	if !bytes.Contains(page, []byte("<html")) {
		return fmt.Errorf("the console page is not HTML")
	}

	// 11. Logging out must invalidate the session.
	if _, _, err := c.post("/api/v1/logout", map[string]any{}); err != nil {
		return err
	}
	// The session endpoint is intentionally reachable without a session: it
	// answers "are you logged in?" rather than "here is the configuration".
	// The assertion is therefore on its verdict, not on its status code.
	status, body, err = c.get("/api/v1/session", true)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("/api/v1/session returned %d after a logout, want 200", status)
	}
	var sess map[string]any
	if err := json.Unmarshal(body, &sess); err != nil {
		return fmt.Errorf("decode /api/v1/session: %w", err)
	}
	if authed, _ := sess["authenticated"].(bool); authed {
		return fmt.Errorf("the session survived a logout")
	}

	// 12. The protected endpoints must be unreachable again.
	if status, _, err = c.get("/api/v1/status", true); err != nil {
		return err
	}
	if status != http.StatusUnauthorized {
		return fmt.Errorf("/api/v1/status returned %d after a logout, want 401", status)
	}
	return nil
}

func (c *client) login(user, pass string) error {
	body, err := json.Marshal(map[string]string{"username": user, "password": pass})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.base+"/api/v1/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login returned %d", resp.StatusCode)
	}
	return nil
}

func (c *client) get(path string, auth bool) (int, []byte, error) {
	return c.do(http.MethodGet, path, nil, auth)
}

func (c *client) post(path string, payload any) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	return c.do(http.MethodPost, path, body, true)
}

func (c *client) do(method, path string, body []byte, auth bool) (int, []byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// A non-browser client that is not the console must not be able to reach
	// the API by spoofing a forwarding header.
	req.Header.Set("X-Forwarded-For", "203.0.113.7")

	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}
