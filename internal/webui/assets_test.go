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
