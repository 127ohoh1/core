package cli

import (
	"errors"
	"net/url"
	"os/exec"
	"runtime"
)

// openBrowser hands an https link to the desktop's default browser. The link
// comes from the server, so anything but https is refused rather than handed
// to a handler that might run it.
func openBrowser(link string) error {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("refusing to open a non-https link")
	}
	// The argument is a parsed https URL (it starts with "https://", so it can
	// never be read as an option) passed as one argv entry, with no shell.
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u.String()) // #nosec G204 -- validated https URL, single argument, no shell
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u.String()) // #nosec G204 -- validated https URL, single argument, no shell
	default:
		cmd = exec.Command("xdg-open", u.String()) // #nosec G204 -- validated https URL, single argument, no shell
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
