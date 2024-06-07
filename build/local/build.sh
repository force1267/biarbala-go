#!/bin/sh

has_go_mod=$(ls | grep "go.mod")
if [ -z "$has_go_mod" ]; then
    echo "Not in project root"
    exit 1
fi

go get ./...

mkdir -p release
go build -o ./release ./cmd/...
