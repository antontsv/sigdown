package sigdown

import (
	"context"
	"strings"
	"testing"
	"time"
)

func newDownloader(key string, t *testing.T) *Downloader {
	downloader, err := New(testKey)
	if err != nil {
		t.Fatalf("unexpected error creating downloader: %v", err)
		return nil
	}
	return downloader
}

func TestDownloaderErrors(t *testing.T) {
	url := "https://git.io/all.files"
	sigurl := url + ".asc"

	const defDuration = 10 * time.Second

	type testCase struct {
		name   string
		mbytes int
		mtime  time.Duration
		err    string
	}

	tt := []testCase{
		{
			name:   "Large downloads terminate",
			mbytes: 100,
			mtime:  defDuration,
			err:    "reached max bytes allowed to download",
		},
		{
			name:   "Long downloads terminate",
			mbytes: 100,
			mtime:  10 * time.Millisecond,
			err:    "was not able to download required content in allowed time",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			downloader := newDownloader(testKey, t)
			downloader.MaxBytes = tc.mbytes
			downloader.MaxTime = tc.mtime
			_, err := downloader.Download(context.Background(), url, sigurl)
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("excepted error: %s, but got: %v", tc.err, err)
			}
		})
	}

}

func TestInvalidKeyError(t *testing.T) {

	tt := []struct {
		name string
		key  string
	}{
		{
			name: "Partial key",
			key:  testKey[0 : len(testKey)/2],
		},
		{
			name: "Empty key",
			key:  "",
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.key)
			if err == nil || !strings.HasPrefix(err.Error(), "bad PGP key:") {
				t.Errorf("expected error: %s, but got: %v", "bad PGP key", err)
			}
		})
	}
}

func TestURLWithoutSig(t *testing.T) {
	url := "https://gist.github.com/antontsv/2c8b4a00ec778e20227e49e8f38aaf93"
	sigurl := url + ".asc"

	downloader := newDownloader(testKey, t)
	_, err := downloader.Download(context.Background(), url, sigurl)
	if err == nil || !strings.HasPrefix(err.Error(), "Could not download signature") ||
		!strings.Contains(err.Error(), "unexpected HTTP response code") {
		t.Error("Expected failure to download non-existing signature file")
	}
}

func TestSupportAbort(t *testing.T) {
	url := "https://git.io/all.files"
	sigurl := url + ".asc"

	downloader := newDownloader(testKey, t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(5*time.Millisecond, cancel)
	_, err := downloader.Download(ctx, url, sigurl)
	if err == nil || err.Error() != "operation was canceled" {
		t.Errorf("Expected failure to user abort using context: %v", err)
	}
}

func TestSignedWithDifferentKey(t *testing.T) {
	url := "https://git.io/all.files"
	sigurl := url + ".asc"

	downloader := newDownloader(testKey, t)
	c, err := downloader.Download(context.Background(), url, sigurl)
	if err == nil || !strings.Contains(err.Error(), "file and signature mismatch") {
		t.Errorf("Expected signature mismatch failure: %v", err)
	}
	if c != nil {
		t.Errorf("Expected empty content, got: %s", c.Content)
	}
}

var testKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: This key is used for testing purposes only, DO NOT use it!

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
=Qmvr
-----END PGP PUBLIC KEY BLOCK-----
`
