# HTTP with PGP check [![Build Status](https://travis-ci.org/antontsv/sigdown.svg?branch=master)](https://travis-ci.org/antontsv/sigdown) [![Go Report Card](https://goreportcard.com/badge/github.com/antontsv/sigdown)](https://goreportcard.com/report/github.com/antontsv/sigdown)

In case you have some content to download from a remote server, which also provides PGP signature download, than you can use this go package to verify signature before using the content from remote server

Example
=======

```go

import (
	"context"
	"fmt"
	"log"

	"github.com/antontsv/sigdown"
)

func main() {
	url := "https://git.io/all.files"
	sigurl := url + ".asc"

    // Value of testKey for this example is here:
    // https://github.com/antontsv/sigdown/blob/master/example_test.go#L33
	downloader, err := sigdown.New(testKey) 
	if err != nil {
		log.Fatalf("unexpected error while creating downloader: %v", err)
	}

	download, err := downloader.Download(context.Background(), url, sigurl)
	if err != nil {
		log.Fatalf("failed to download %s with signature verification, error: %v", url, err)
	}

	fmt.Println(download.Content)
}

```

More
====
[![GoDoc](https://godoc.org/github.com/antontsv/sigdown?status.svg)](https://godoc.org/github.com/antontsv/sigdown)
