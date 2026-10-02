module github.com/127ohoh1/core

go 1.24.0

// Builds must use a patched standard library: govulncheck reports 18 standard
// library vulnerabilities for go1.26.0 and none from go1.26.6 onward.
toolchain go1.26.8

require golang.org/x/crypto v0.43.0

require (
	golang.org/x/net v0.45.0 // indirect
	golang.org/x/text v0.30.0 // indirect
)
