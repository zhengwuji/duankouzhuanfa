package webui

import (
	"io/fs"
	"regexp"
	"strconv"
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

// The guide view is the third contract. It is documentation shipped inside the
// binary, so nothing else would catch it drifting: a nav button that points at a
// view the script never registered renders an empty page with a JS error, and a
// copy button that cannot copy is worse than no button, because the operator
// pastes nothing and blames the command.

// TestEveryNavEntryHasAView is the regression test for the failure mode this
// view could introduce: index.html and app.js both name the views, and adding
// one to only one of them produces a nav button that silently does nothing.
func TestEveryNavEntryHasAView(t *testing.T) {
	html := readAsset(t, "index.html")
	js := readAsset(t, "app.js")

	// Collect data-view values from the shell.
	nav := regexp.MustCompile(`data-view="([^"]+)"`).FindAllStringSubmatch(html, -1)
	if len(nav) == 0 {
		t.Fatal("index.html has no data-view nav entries; this test would pass vacuously")
	}

	// Collect the registered view keys. The block is a plain object literal, so
	// it is read as text rather than parsed: a dependency for one test would be
	// out of proportion, as with findRule below.
	block := js[strings.Index(js, "const VIEWS = {"):]
	if end := strings.Index(block, "\n};"); end >= 0 {
		block = block[:end]
	}
	registered := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s*([a-zA-Z]+):\s*\{`).FindAllStringSubmatch(block, -1) {
		registered[m[1]] = true
	}
	if len(registered) == 0 {
		t.Fatal("could not read any view names out of the VIEWS object")
	}

	for _, m := range nav {
		if !registered[m[1]] {
			t.Errorf("index.html offers a nav entry for %q but app.js registers no such view, "+
				"so clicking it shows an empty page", m[1])
		}
	}
	// And the reverse: a registered view with no button is unreachable.
	seen := map[string]bool{}
	for _, m := range nav {
		seen[m[1]] = true
	}
	for name := range registered {
		if !seen[name] {
			t.Errorf("app.js registers the view %q but index.html has no nav entry for it, "+
				"so the operator cannot reach it", name)
		}
	}
}

// TestGuideMatchesTheConsoleItRunsIn pins the part of the guide that would be
// wrong rather than merely missing.
//
// A server-side console has no client half: showing it the "add a relay server"
// and "new forwarding rule" steps would be instructions for a different machine,
// and an operator who follows them finds fields that are not there. The guide
// therefore branches on the mode, and both branches must exist.
func TestGuideMatchesTheConsoleItRunsIn(t *testing.T) {
	js := readAsset(t, "app.js")

	for _, want := range []string{
		"const isServer = mode === 'server' || mode === 'both';",
		"const isClient = mode === 'client' || mode === 'both';",
		"if (isServer) {",
		"if (isClient) {",
	} {
		if !strings.Contains(js, want) {
			t.Errorf("the guide does not branch on the console's mode (missing %q), "+
				"so it tells at least one mode to use a page it does not have", want)
		}
	}

	// install.sh is the server installer. A client-mode console that tells the
	// operator to run it sends them looking for a file that is not on their
	// machine, so that row must sit inside the server branch of the
	// troubleshooting table — not merely somewhere in the guide.
	//
	// The segment is cut out explicitly rather than searched from the top: the
	// guide has two `if (isServer)` blocks (the step list and the troubleshooting
	// rows), and a looser search would keep passing after the one under test was
	// deleted.
	start := strings.Index(js, "const trouble = [")
	if start < 0 {
		t.Fatal("the troubleshooting rows are no longer built from a `trouble` array; this test needs updating")
	}
	seg := js[start:]
	if end := strings.Index(seg, "guideTable(['现象'"); end >= 0 {
		seg = seg[:end]
	}
	open := strings.Index(seg, "if (isServer) {")
	if open < 0 {
		t.Fatal("the troubleshooting rows are no longer gated on the mode; this test needs updating")
	}
	shared := seg[:open]
	serverSide, clientSide := seg[open:], ""
	if mid := strings.Index(seg[open:], "} else {"); mid >= 0 {
		serverSide = seg[open : open+mid]
		clientSide = seg[open+mid:]
	}

	const installRow = "install.sh --reset-password"
	if strings.Contains(shared, installRow) {
		t.Error("the install.sh row is in the shared troubleshooting rows, so a client-mode " +
			"console offers the operator a script that only exists on a server")
	}
	if !strings.Contains(serverSide, installRow) {
		t.Error("the server branch no longer tells the operator how to reset a forgotten console " +
			"password, which is the one recovery path for a hash-only password")
	}
	if strings.Contains(clientSide, installRow) {
		t.Error("the client branch mentions the server installer")
	}
	// The client half must still have its own answer for the same problem.
	if !strings.Contains(clientSide, "porttransit reset-password") {
		t.Error("a client-mode console has no way to recover a forgotten password")
	}
}

// TestGuideCommandsAreCopyable keeps the tutorial's commands from becoming
// retype-only. The clipboard API needs a secure context and this console is
// normally opened over plain HTTP at an IP, so the fallback path is the one that
// actually runs in practice — and it must say what to do when it fails rather
// than reporting success it did not achieve.
func TestGuideCommandsAreCopyable(t *testing.T) {
	js := readAsset(t, "app.js")
	css := readAsset(t, "app.css")

	if !strings.Contains(js, "async function copyText(") {
		t.Fatal("the guide has no copy helper; this test needs updating")
	}
	if !strings.Contains(js, "navigator.clipboard && window.isSecureContext") {
		t.Error("the copy helper uses the clipboard API without checking for a secure context, " +
			"where it is undefined — which is the normal case for an HTTP console at an IP")
	}
	if !strings.Contains(js, "document.execCommand('copy')") {
		t.Error("the copy helper has no fallback for a non-secure context, so the copy " +
			"buttons do nothing on the deployment the guide is written for")
	}
	// Failing must not look like succeeding.
	if !strings.Contains(js, "'浏览器未授权自动复制，内容已选中，请按 Ctrl+C（Mac 为 ⌘C）'") {
		t.Error("a copy that could not happen reports nothing the operator can act on")
	}

	// The copy button is absolutely positioned over the code block, so the block
	// must reserve room for it or the first line renders underneath the button.
	// Checking for the word "padding" would pass on `padding: 0`, so the reserved
	// right-hand width is read out and compared against the button's own width.
	rule := findRule(css, ".guide-code")
	if rule == "" {
		t.Fatal("app.css has no .guide-code rule; this test needs updating")
	}
	right, ok := paddingRight(rule)
	if !ok {
		t.Error("the code block has no padding, so its first line renders under the copy button")
	} else if right < 60 {
		t.Errorf("the code block reserves only %gpx on the right, less than the copy button "+
			"occupies, so long first lines run under it", right)
	}

	// The absolute positioning only works against a positioned ancestor.
	if r := findRule(css, ".guide-codewrap"); r == "" || !strings.Contains(r, "position: relative") {
		t.Error("the code wrapper is not positioned, so the copy button escapes to the page " +
			"and lands wherever the nearest positioned ancestor is")
	}
	if r := findRule(css, ".guide-copy"); r == "" || !strings.Contains(r, "position: absolute") {
		t.Error("the copy button is not positioned over the code block")
	}
}

// paddingRight returns the right-hand padding of a declaration block in pixels.
//
// The padding shorthand is expanded the way CSS does it: one value applies to
// every side, two to vertical then horizontal, four to top/right/bottom/left.
func paddingRight(rule string) (float64, bool) {
	m := regexp.MustCompile(`padding:\s*([^;]+);`).FindStringSubmatch(rule)
	if m == nil {
		return 0, false
	}
	fields := strings.Fields(m[1])
	// Pull the px value for the right side.
	var idx int
	switch len(fields) {
	case 1:
		idx = 0
	case 2, 3:
		idx = 1
	default:
		idx = 1
	}
	val := strings.TrimSuffix(fields[idx], "px")
	n, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// TestGuideIsReachableFromTheSidebar is deliberately narrow: it is the one thing
// about the new page that a screenshot would not catch, namely that the entry
// sits in the nav the operator actually looks at.
func TestGuideIsReachableFromTheSidebar(t *testing.T) {
	html := readAsset(t, "index.html")
	if !strings.Contains(html, `<button class="nav-item" data-view="guide">使用说明</button>`) {
		t.Error("the guide is not offered in the sidebar nav")
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
