#!/bin/sh
set -eu
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
export CHROME
GOCACHE="${GOCACHE:-/tmp/trusttunnel-go-build}"
GOMODCACHE="${GOMODCACHE:-/tmp/trusttunnel-go-mod}"
export GOCACHE GOMODCACHE
go test -tags=browser ./internal/webui -run TestBrowserOfflineAssets -count=1
