package webui

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

// The console's front end is an embedded stylesheet plus a script, and the two
// have a contract that no Go test would otherwise notice: app.js reveals and
// hides sections by flipping the `hidden` property, and app.css must therefore
// never out-specify that attribute for those sections.
//
// It did. `#app { display: flex }` and `.login-wrap { display: flex }` are
// author declarations, and an author `display` beats the user-agent
// `[hidden] { display: none }` — so the login form and the console frame were
// painted simultaneously on every load. A stale session then produced the
// "登录已过期，请重新登录" banner on top of a console that was visibly there,
// which reads as a broken console rather than as a fresh visitor.
//
// These tests are deliberately about the files as shipped, not about a browser
// simulation: the asset bytes are what the relay serves, so checking them is
// checking the deployed behaviour.

// TestStylesheetHonoursTheHiddenAttribute is the regression test for the
// console showing the login form and the app at the same time.
func TestStylesheetHonoursTheHiddenAttribute(t *testing.T) {
	css := readAsset(t, "app.css")

	// The blanket rule is what makes every current and future toggle work,
	// rather than a per-element rule that has to be remembered each time.
	blanket := regexp.MustCompile(`\[hidden\]\s*\{[^}]*display:\s*none\s*!important`)
	if !blanket.MatchString(css) {
		t.Error("app.css has no `[hidden] { display: none !important }` rule: " +
			"any element whose class declares a display value will ignore its own hidden attribute, " +
			"so the login form and the console can render at the same time")
	}

	// Both halves of the switch are affected, which is why a per-element rule
	// was not enough: #app declares a display value directly, and #login gets
	// one from the .login-wrap class. Naming them keeps the rule from looking
	// like it could be dropped.
	for _, sel := range []string{"#app", ".login-wrap"} {
		rule := findRule(css, sel)
		if rule == "" {
			t.Errorf("app.css has no rule for %s; if that rule was removed, update this test "+
				"rather than leaving a stale expectation behind", sel)
			continue
		}
		if !strings.Contains(rule, "display:") {
			continue // nothing to override; the user-agent rule is enough
		}
		if !blanket.MatchString(css) {
			t.Errorf("%s declares a display value, so its hidden attribute is ineffective without the blanket rule", sel)
		}
	}
}

// TestScriptTogglesOnlyHiddenProtectedElements pins the other half of the
// contract: every element the script hides must be one the stylesheet cannot
// out-specify. It looks for the selectors passed to the hidden assignment.
func TestScriptTogglesOnlyHiddenProtectedElements(t *testing.T) {
	js := readAsset(t, "app.js")
	css := readAsset(t, "app.css")

	blanket := regexp.MustCompile(`\[hidden\]\s*\{[^}]*display:\s*none\s*!important`).MatchString(css)

	toggled := regexp.MustCompile(`\$\('([^']+)'\)\.hidden\s*=`).FindAllStringSubmatch(js, -1)
	if len(toggled) == 0 {
		t.Fatal("no .hidden toggles found in app.js; this test would pass vacuously")
	}
	for _, m := range toggled {
		sel := m[1]
		rule := findRule(css, sel)
		if rule == "" || !strings.Contains(rule, "display:") {
			continue // no display value: the user-agent rule still applies
		}
		if !blanket {
			t.Errorf("%s is hidden by app.js and declares a display value in app.css, but no "+
				"`[hidden] { display: none !important }` rule protects it", sel)
		}
	}
}

// TestLoginFailureIsNotReportedAsAnExpiredSession covers the message an
// operator actually saw: mistyping the password answered with
// "登录已过期，请重新登录", which sends them looking for a session problem
// instead of at the field they got wrong.
func TestLoginFailureIsNotReportedAsAnExpiredSession(t *testing.T) {
	js := readAsset(t, "app.js")

	// The 401 branch must prefer the server's own message.
	if !strings.Contains(js, "const serverMessage = data &&") {
		t.Error("the 401 branch does not read the server's error message")
	}
	if !strings.Contains(js, "throw new Error(serverMessage ||") {
		t.Error("the 401 branch does not prefer the server's message over the generic wording")
	}
	// A rejected login must not clear the password field: the operator has to
	// retype it, and the field being emptied is what made a single typo look
	// like the console refusing every attempt.
	if !strings.Contains(js, "waitingOnLogin") {
		t.Error("app.js does not distinguish a rejected login from an expired session, " +
			"so a 401 on the login form still resets the form and reports an expiry")
	}
	if !strings.Contains(js, "if (!waitingOnLogin) showLogin();") {
		t.Error("the 401 branch shows the login form unconditionally, which wipes the password on a failed login")
	}
}

// The host panels are the second contract between the two assets: the dashboard
// renders a machine's resources and its outbound network quality, and the
// failure modes that matter are the quiet ones — a panel that shows zeroes
// because nothing has been measured yet, or a probe result labelled as a
// measurement it is not, both read as good news.

// TestDashboardDegradesToAPanelNotTheWholePage proves a host that cannot be
// sampled costs the operator one card, not the console.
//
// /api/v1/host and /api/v1/status are fetched separately and the host failure is
// caught locally. Sharing one try block would blank the dashboard — including
// the relay listener table, which is the reason the page is open — because a
// side panel could not read /proc.
func TestDashboardDegradesToAPanelNotTheWholePage(t *testing.T) {
	js := readAsset(t, "app.js")

	// The host request must be inside its own try, with a fallback value that
	// carries the reason through to the panel.
	if !strings.Contains(js, "hostInfo = await api('/api/v1/host');") {
		t.Fatal("the dashboard does not request /api/v1/host")
	}
	if !strings.Contains(js, "hostInfo = { available: false, reason: err.message };") {
		t.Error("a failed host request does not fall back to an unavailable panel, " +
			"so the whole dashboard fails with it")
	}

	// The status request must still be awaited outside that try, so a broken
	// host panel cannot take the counters down with it.
	if !strings.Contains(js, "await api('/api/v1/status');") {
		t.Error("the dashboard no longer requests /api/v1/status")
	}

	// Both panels are appended unconditionally: an unavailable host is
	// explained in place rather than silently omitted, because a card that
	// disappears is indistinguishable from a build that never had it.
	for _, call := range []string{"hostPanel(hostInfo)", "hostPingPanel(hostInfo)"} {
		if !strings.Contains(js, "host.append("+call+");") {
			t.Errorf("the dashboard does not render %s", call)
		}
	}
}

// TestUnavailableHostIsExplainedNotHidden pins the wording of the missing-host
// case, which is the one an operator on an unsupported platform sees.
func TestUnavailableHostIsExplainedNotHidden(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "'此平台不支持主机资源采集'") {
		t.Error("there is no explanation for a host that cannot be sampled, so the " +
			"panel would either be blank or absent with no reason given")
	}
	if !strings.Contains(js, "class: 'empty'") {
		t.Error("the unavailable host is not rendered as an empty-state message")
	}
}

// TestUnmeasuredPingIsNotShownAsZeroLatency is the regression test for a card
// that read 0 ms / 0% loss before the first probe had run.
//
// Zeroes are the best possible reading on this panel, so showing them for "not
// measured yet" is worse than showing nothing: it reports a perfect network
// that has not been tested.
func TestUnmeasuredPingIsNotShownAsZeroLatency(t *testing.T) {
	js := readAsset(t, "app.js")

	if !strings.Contains(js, "if (!ping.lastAt) {") {
		t.Error("the outbound-quality card renders its figures before any probe has " +
			"completed, so an unmeasured network reads as a perfect one")
	}
	if !strings.Contains(js, "'正在测量…'") {
		t.Error("the pending state does not say it is still measuring")
	}
}

// TestProbeMethodIsLabelledHonestly proves the console never presents a TCP
// handshake as an ICMP round trip.
//
// The two are different measurements — one times the network path, the other
// times a service answering — and the fallback is invisible to the reader
// unless the method is printed next to the number.
func TestProbeMethodIsLabelledHonestly(t *testing.T) {
	js := readAsset(t, "app.js")

	// Each method the Go side can report must have its own label, including the
	// mixed case where the aggregate average is not a like-for-like number.
	for _, pair := range []struct{ method, label string }{
		{"'icmp'", "'ICMP'"},
		{"'tcp'", "'TCP 握手'"},
		{"'mixed'", "'ICMP / TCP 混合'"},
	} {
		needle := "case " + pair.method + ": return " + pair.label + ";"
		if !strings.Contains(js, needle) {
			t.Errorf("no label for %s: the card would present the measurement "+
				"without saying how it was taken", pair.method)
		}
	}

	// The method has to be on screen, not just computed.
	if !strings.Contains(js, "测量方式：${pingMethodLabel(ping.method)}") {
		t.Error("the measured method is not shown on the outbound-quality card")
	}
	if !strings.Contains(js, "el('td', { text: pingMethodLabel(t.method) })") {
		t.Error("the per-target table does not show how each target was measured")
	}
}

// TestHostRefreshStopsWhenItShould covers the polling loop's exits. A timer
// that outlives its view keeps hitting an authenticated endpoint from whatever
// screen the operator moved to, and one that ignores a backgrounded tab keeps
// waking the machine to redraw something nobody is looking at.
func TestHostRefreshStopsWhenItShould(t *testing.T) {
	js := readAsset(t, "app.js")

	// Leaving the dashboard stops the timer.
	if !strings.Contains(js, "if (state.view !== 'dashboard') { stopHostRefresh(); return; }") {
		t.Error("the host refresh loop keeps running after the operator leaves the dashboard")
	}
	// A hidden tab is not polled.
	if !strings.Contains(js, "if (document.hidden) return;") {
		t.Error("the host refresh loop polls while the tab is in the background")
	}
	// A replaced view ends the loop rather than throwing on every tick.
	if !strings.Contains(js, "if (!anchor) { stopHostRefresh(); return; }") {
		t.Error("the host refresh loop does not stop when its anchor element is gone")
	}
	// Showing any view and showing the login form both cancel it: the login
	// screen is unauthenticated, so every tick there would be a 401.
	if strings.Count(js, "stopHostRefresh();") < 4 {
		t.Error("stopHostRefresh is not called on every path that leaves the dashboard")
	}
	if !strings.Contains(js, "function showLogin()") {
		t.Fatal("showLogin is gone; this test needs updating")
	}
	login := js[strings.Index(js, "function showLogin()"):]
	if end := strings.Index(login, "\n}"); end >= 0 {
		login = login[:end]
	}
	if !strings.Contains(login, "stopHostRefresh();") {
		t.Error("the login screen does not stop the host refresh loop, so a signed-out " +
			"console keeps polling a protected endpoint and collecting 401s")
	}
}

// TestHostRefreshReplacesOnlyItsOwnCards keeps the poll from rebuilding the
// page. Re-rendering the dashboard on every tick would reset the scroll
// position and rebuild the relay table under the operator's cursor, which makes
// a page that refreshes itself unusable for the thing it is there to show.
func TestHostRefreshReplacesOnlyItsOwnCards(t *testing.T) {
	js := readAsset(t, "app.js")

	start := strings.Index(js, "async function refreshHostPanels()")
	if start < 0 {
		t.Fatal("refreshHostPanels is gone; this test needs updating")
	}
	body := js[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}

	if !strings.Contains(body, "anchor.replaceWith(hostPanel(info))") {
		t.Error("the refresh does not replace the host card in place")
	}
	if !strings.Contains(body, "ping.replaceWith(hostPingPanel(info))") {
		t.Error("the refresh does not replace the outbound-quality card in place")
	}
	if strings.Contains(body, "show(state.view)") || strings.Contains(body, "refreshCurrent()") {
		t.Error("the host refresh re-renders the whole dashboard, which resets scroll " +
			"position and rebuilds every other table on the page")
	}
}

// readAsset returns an embedded console asset as text.
func readAsset(t *testing.T, name string) string {
	t.Helper()
	data, err := fs.ReadFile(assetsFS, "assets/"+name)
	if err != nil {
		t.Fatalf("read embedded %s: %v", name, err)
	}
	return string(data)
}

// findRule returns the declaration block of the first rule whose selector list
// contains sel exactly, or "" when there is none. It descends into at-rule
// bodies (the stylesheet has a prefers-color-scheme block) and is brace-aware
// because those bodies nest.
//
// Comments are removed first: this stylesheet documents itself with snippets
// such as `#app { display: flex }` in prose, and those braces would otherwise
// be read as real rules.
//
// It is a small scanner rather than a CSS parser because the stylesheet is
// hand-written and flat, and a dependency for one test would be out of
// proportion.
func findRule(css, sel string) string {
	return scanRules(stripComments(css), sel)
}

// stripComments removes /* … */ comments, which never nest in CSS.
func stripComments(css string) string {
	var b strings.Builder
	for {
		start := strings.Index(css, "/*")
		if start < 0 {
			b.WriteString(css)
			return b.String()
		}
		b.WriteString(css[:start])
		end := strings.Index(css[start+2:], "*/")
		if end < 0 {
			return b.String() // unterminated comment: drop the rest
		}
		css = css[start+2+end+2:]
	}
}

func scanRules(css, sel string) string {
	for i := 0; i < len(css); {
		open := strings.IndexByte(css[i:], '{')
		if open < 0 {
			return ""
		}
		open += i
		close := matchingBrace(css, open)
		if close < 0 {
			return ""
		}

		prelude := strings.TrimSpace(css[i:open])
		switch {
		case strings.HasPrefix(prelude, "@media"), strings.HasPrefix(prelude, "@supports"):
			// An at-rule wraps more rules; look inside it as well.
			if hit := scanRules(css[open+1:close], sel); hit != "" {
				return hit
			}
		case strings.HasPrefix(prelude, "@"):
			// @keyframes and friends contain no selectors we care about.
		default:
			for _, part := range strings.Split(prelude, ",") {
				if strings.TrimSpace(part) == sel {
					return css[open+1 : close]
				}
			}
		}
		i = close + 1
	}
	return ""
}

// matchingBrace returns the index of the '}' that closes the '{' at open,
// accounting for nested braces, or -1 when the input is unbalanced.
func matchingBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
