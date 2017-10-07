package sigdown_test

import (
	"context"
	"fmt"
	"log"

	"github.com/antontsv/sigdown"
)

// Example downloads content that has a
// PGP signature available for verification using testKey listed below
func Example() {
	url := "https://git.io/all.files"
	sigurl := url + ".asc"

	downloader, err := sigdown.New(testKey)
	if err != nil {
		log.Fatalf("unexpected error creating downloader: %v", err)
	}

	download, err := downloader.Download(context.Background(), url, sigurl)
	if err != nil {
		log.Fatalf("failed to download %s with signature verification, error: %v", url, err)
	}

	for _, name := range download.Signers {
		fmt.Printf("Signed by: %s", name)
	}
	//Output: Signed by: Anton Tsviatkou
}

var testKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: antontsv

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
Q9yHDCiJn/+13NMTJE+kxJQ=
=oCRa
-----END PGP PUBLIC KEY BLOCK-----
`
