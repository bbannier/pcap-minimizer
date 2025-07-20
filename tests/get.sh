#!/usr/bin/env sh

set -eu
tshark -r "$1" 'http.request.uri == "/a"' | grep -q HTTP
