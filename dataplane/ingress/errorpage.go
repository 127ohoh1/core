package ingress

import (
	"html/template"
	"net/http"
	"strings"
)

// wantsHTML reports whether the caller is a browser asking for a page.
// Everything else (curl, the CLI, API clients) keeps the JSON envelope, so
// the machine-readable contract is unchanged.
func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// errorCopy is what a visitor of someone else's tunneled site is told. They
// are not the developer: no protocol or infrastructure terms.
var errorCopy = map[string][2]string{
	"endpoint_not_found":  {"This site isn't online", "Nothing is being served at this address right now."},
	"tunnel_offline":      {"This site is offline", "The app behind this address isn't accepting visitors right now."},
	"tunnel_lost":         {"This site is offline", "The connection to the app behind this address was lost. Try again in a moment."},
	"origin_unreachable":  {"This site is offline", "The app behind this address isn't responding. It may be stopped or restarting."},
	"origin_timeout":      {"This site took too long to respond", "The app behind this address didn't answer in time."},
	"origin_error":        {"This site ran into a problem", "The app behind this address couldn't complete the request."},
	"bad_origin_response": {"This site ran into a problem", "The app behind this address sent a response that couldn't be delivered."},
	"tunnel_busy":         {"This site is busy", "Too many requests are in progress. Try again in a moment."},
}

var errorPage = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{{.Heading}}</title>
<style>
:root{--bg:#fbf8f2;--fg:#161310;--muted:#6b6259;--line:#e3dccf}
@media (prefers-color-scheme:dark){:root{--bg:#161310;--fg:#fbf8f2;--muted:#a59b90;--line:#2c2620}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font:1rem/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
main{max-width:34rem;width:100%}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 .5rem}
p{margin:0 0 1rem}
.meta{border-top:1px solid var(--line);padding-top:.75rem;margin-top:1.5rem;font-size:.85rem;color:var(--muted)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
</style>
</head>
<body>
<main>
<h1>{{.Heading}}</h1>
<p>{{.Text}}</p>
<p class="meta">This page comes from 127ohoh1, the service that carries this site, not from the site itself. Error <code>{{.Code}}</code> ({{.Status}}), request <code>{{.RequestID}}</code>.</p>
</main>
</body>
</html>
`))

// writeErrorPage renders a platform error for a browser. Only server-side
// values reach the page (code, message, request id); the request's Host,
// path and headers are never reflected.
func writeErrorPage(w http.ResponseWriter, status int, code, msg, reqID string) {
	c, ok := errorCopy[code]
	if !ok {
		c = [2]string{"This request couldn't be completed", msg}
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = errorPage.Execute(w, struct {
		Heading, Text, Code, RequestID string
		Status                         int
	}{c[0], c[1], code, reqID, status})
}
