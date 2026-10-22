package weblog

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseCombined(t *testing.T) {
	line := `203.0.113.7 - - [14/Feb/2026:18:48:01 +0100] "POST /errors/503.php?x=%2e%2e%2f HTTP/1.1" 200 13 "-" "Mozilla/5.0 (X11) \"quoted\"" 0.012 upstream=127.0.0.1:9000`
	r, ok := Parse(FormatCombined, line)
	if !ok {
		t.Fatal("not parsed")
	}
	want := Request{
		Time: time.Date(2026, 2, 14, 17, 48, 1, 0, time.UTC), IP: "203.0.113.7", Method: "POST",
		URI: "/errors/503.php?x=%2e%2e%2f", Status: 200, Size: 13, UserAgent: `Mozilla/5.0 (X11) \"quoted\"`,
	}
	if r.Time != want.Time || r.IP != want.IP || r.Method != want.Method || r.URI != want.URI || r.Status != want.Status || r.Size != want.Size || r.UserAgent != want.UserAgent || r.Referer != "" {
		t.Errorf("got %+v\nwant %+v", r, want)
	}
	if r.Path() != "/errors/503.php" || r.query != "x=../" {
		t.Errorf("path %q query %q", r.Path(), r.query)
	}

	for _, bad := range []string{"", "garbage", `1.2.3.4 - - [not a date] "GET / HTTP/1.1" 200 1`} {
		if _, ok := Parse(FormatCombined, bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	if r, ok := Parse(FormatCombined, `198.51.100.1 - - [14/Feb/2026:18:48:01 +0000] "GET /" 404 -`); !ok || r.Size != 0 || r.UserAgent != "" {
		t.Errorf("minimal common log line: %+v %v", r, ok)
	}
}

func TestParseCaddy(t *testing.T) {
	line := `{"level":"info","ts":1771091281.5,"request":{"remote_ip":"10.0.0.2","client_ip":"203.0.113.9","method":"GET","uri":"/a%252e%252e/b?q=1","headers":{"User-Agent":["curl/8"],"Referer":["https://x"]}},"status":404,"size":12}`
	if DetectFormat(line) != FormatCaddy {
		t.Fatal("format not detected")
	}
	r, ok := Parse(FormatCaddy, line)
	if !ok || r.IP != "203.0.113.9" || r.Status != 404 || r.UserAgent != "curl/8" || r.Referer != "https://x" {
		t.Fatalf("got %+v", r)
	}
	if r.Path() != "/a../b" {
		t.Errorf("double encoding not decoded: %q", r.Path())
	}
	if r.Time.Unix() != 1771091281 || r.Time.Nanosecond() != 500_000_000 {
		t.Errorf("time = %v", r.Time)
	}
	if _, ok := Parse(FormatCaddy, `{"msg":"not a request"}`); ok {
		t.Error("parsed a non-request entry")
	}
}

func req(method, uri string, status int, ua string) *Request {
	r, _ := Parse(FormatCombined, fmt.Sprintf(`203.0.113.7 - - [14/Feb/2026:18:48:01 +0000] "%s %s HTTP/1.1" %d 100 "-" "%s"`, method, uri, status, ua))
	return &r
}

func rules(hits []Hit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Rule+":"+h.Severity)
	}
	return out
}

func TestRules(t *testing.T) {
	tests := []struct {
		r    *Request
		want []string
	}{
		{req("GET", "/media/catalog/x.php", 200, "-"), []string{"script_in_upload_path:critical"}},
		{req("POST", "/media/catalog/x.php", 404, "-"), []string{"script_in_upload_path:high"}},
		{req("GET", "/media/catalog/x.php/a.jpg", 200, "-"), []string{"script_in_upload_path:critical"}},
		{req("GET", "/wp-content/uploads/2026/x.phtml", 403, "-"), []string{"script_in_upload_path:high"}},
		{req("GET", "/wso.php", 404, "-"), []string{"known_webshell_name:low"}},
		{req("POST", "/wso.php", 404, "-"), []string{"known_webshell_name:high"}},
		{req("GET", "/tools/c99.php/x", 200, "-"), []string{"known_webshell_name:critical"}},
		{req("GET", "/x.php?cmd=whoami", 200, "-"), []string{"command_in_parameters:critical"}},
		{req("GET", "/search?c=cat%20/etc/passwd", 404, "-"), []string{"command_in_parameters:high", "path_traversal:medium"}},
		{req("POST", "/get.php", 200, "-"), []string{"post_to_get_only_endpoint:high"}},
		{req("POST", "/static/app.js", 200, "-"), []string{"post_to_static_file:medium"}},
		{req("GET", "/.env", 200, "-"), []string{"sensitive_file:high"}},
		{req("GET", "/.git/config", 404, "-"), []string{"sensitive_file:low"}},
		{req("GET", "/index.php?file=..%2F..%2Fetc%2Fpasswd", 200, "-"), []string{"path_traversal:high"}},
		{req("GET", "/p?id=1%20UNION%20SELECT%201,2", 200, "-"), []string{"sql_injection:medium"}},
		{req("GET", "/", 200, "${jndi:ldap://x/a}"), []string{"injection_probe:medium"}},
		{req("GET", "/", 404, "sqlmap/1.7"), []string{"scanner_user_agent:low"}},
		{req("GET", "/catalog/product/view", 200, "Mozilla"), nil},
		{req("POST", "/checkout/cart/add", 200, "Mozilla"), nil},
	}
	for _, tt := range tests {
		got := rules(NewAnalyzer().Analyze(tt.r))
		if !slices.Equal(got, tt.want) {
			t.Errorf("%s %s %d: got %v, want %v", tt.r.Method, tt.r.URI, tt.r.Status, got, tt.want)
		}
	}
}

// A session file uploaded through the customer address endpoint and then loaded by a failing
// guest cart call is the chain of a known deserialization exploit; each half alone is not.
func TestUploadThenTriggerChain(t *testing.T) {
	a := NewAnalyzer()
	upload := req("POST", "/customer/address_file/upload", 200, "-")
	trigger := req("PUT", "/rest/default/V1/guest-carts/abc/collect-totals", 500, "-")
	other := *trigger
	other.IP = "198.51.100.1"

	if got := rules(a.Analyze(trigger)); len(got) != 0 {
		t.Errorf("trigger without upload: %v", got)
	}
	if got := rules(a.Analyze(upload)); !slices.Equal(got, []string{"sessionreaper_upload:high"}) {
		t.Errorf("upload: %v", got)
	}
	if got := rules(a.Analyze(&other)); len(got) != 0 {
		t.Errorf("trigger from another IP: %v", got)
	}
	later := *trigger
	later.Time = upload.Time.Add(time.Hour)
	if got := rules(a.Analyze(&later)); !slices.Equal(got, []string{"sessionreaper_chain:critical"}) {
		t.Errorf("chain: %v", got)
	}
	tooLate := *trigger
	tooLate.Time = upload.Time.Add(48 * time.Hour)
	if got := rules(a.Analyze(&tooLate)); len(got) != 0 {
		t.Errorf("outside the window: %v", got)
	}
}

func TestLoginBruteForceFiresOnce(t *testing.T) {
	a := NewAnalyzer()
	fired := 0
	for i := range 200 {
		r := req("POST", "/wp-login.php", 200, "-")
		r.Time = r.Time.Add(time.Duration(i) * time.Second)
		for _, h := range a.Analyze(r) {
			if h.Rule == "login_bruteforce" {
				fired++
			}
		}
	}
	if fired != 1 {
		t.Errorf("fired %d times, want once", fired)
	}
	if n := len(a.logins["203.0.113.7"]); n > bruteForceLimit+1 {
		t.Errorf("kept %d attempts for one IP", n)
	}
}

func TestRedact(t *testing.T) {
	tests := map[string]string{
		"/account/reset?token=SECRET123&path=../../etc/passwd": "/account/reset?token=[redacted]&path=../../etc/passwd",
		"/search?q=shoes&page=2":                               "/search?q=[redacted]&page=[redacted]",
		"/p?id=1%20UNION%20SELECT%201":                         "/p?id=1%20UNION%20SELECT%201",
		"/x.php?cmd=whoami&api_key=abc":                        "/x.php?cmd=whoami&api_key=[redacted]",
		"/plain/path":                                          "/plain/path",
		"/flag?debug&x=":                                       "/flag?debug&x=",
	}
	for in, want := range tests {
		if got := RedactURI(in); got != want {
			t.Errorf("RedactURI(%q) = %q, want %q", in, got, want)
		}
	}
	line := `PHP Fatal error: eval()'d code, request "GET /cb?code=OAUTHCODE&state=x HTTP/1.1"`
	if got := RedactLine(line); strings.Contains(got, "OAUTHCODE") || !strings.Contains(got, "eval()'d code") {
		t.Errorf("RedactLine = %q", got)
	}
	if got := RedactURI("/" + strings.Repeat("a", 1000)); len(got) > maxEvidenceLen+3 {
		t.Errorf("evidence not truncated: %d bytes", len(got))
	}
}
