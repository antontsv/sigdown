// Package sigdown uses net/HTTP and add PGP signature verification
package sigdown

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
)

// SignedContent returns signed context and names of signers
type SignedContent struct {
	// Content that has been confirmed by its detashed signature
	Content []byte
	// Signers represents a list of names of people who signed Content.
	Signers []string
}

// Request has all necessary data to perform HTTP download PGP verification detached signature
type Request struct {
	// URL to download content from
	URL string
	// SigURL should serve detached PGP signature for the content served by URL
	SigURL string
	// MaxBytes spefifies max number of bytes content or signature file
	// can be downloaded from remote site.
	// We do not want remote service or Man-In-The-Middle try to overload
	// Downloader with large files, by having download size limited to appropriate
	// value we will fail fast
	//
	// Default is 1048576 [1MB]
	MaxBytes int
	// Timeout specifies a time limit a Download is allowed to run,
	// including getting content and signature data from remote server
	// and running all checks.
	// Default is 30 seconds
	Timeout time.Duration
}

// Downloader can perform an HTTP download with PGP signature verification
type Downloader interface {
	Download(ctx context.Context, req Request) (*SignedContent, error)
}

// downloader can perform an HTTP download with PGP signature verification
type downloader struct {
	keyring openpgp.EntityList
}

type download struct {
	resType string
	resp    *http.Response
	err     error
}

type result struct {
	content *SignedContent
	err     error
}

// Download resource types
const (
	resContent = "content"
	resSig     = "signature"
)

// New returns new downloader set to verify downloads provided PGP key
func New(pgpPubKey string) (Downloader, error) {
	d := new(downloader)
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pgpPubKey))
	if err != nil {
		return nil, fmt.Errorf("bad PGP key: %v", err)
	}
	d.keyring = keyring
	return d, nil
}

// Download fetches data and PGP signature over HTTP and returns data if signed correctly
func (d *downloader) Download(ctx context.Context, req Request) (*SignedContent, error) {

	url := req.URL
	sigurl := req.SigURL
	timeout := 30 * time.Second
	maxbytes := req.MaxBytes
	if maxbytes <= 0 {
		maxbytes = 1048576
	}
	if req.Timeout != 0 {
		timeout = req.Timeout
	}

	cancelCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	results := make(chan result, 5)
	downloadc := make(chan download, 2)

	downloader := func(name string, url string) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		req = req.WithContext(cancelCtx)
		req.Close = true
		resp, err := http.DefaultClient.Do(req)
		if cancelCtx.Err() != nil {
			return
		}
		if err != nil || resp.StatusCode != http.StatusOK {
			if err == nil {
				err = fmt.Errorf("unexpected HTTP response code %d", resp.StatusCode)
			}
			results <- result{err: fmt.Errorf("Could not download %s from %s: %v", name, url, err)}
			return
		}
		downloadc <- download{resType: name, resp: resp}
	}

	go downloader(resContent, url)
	go downloader(resSig, sigurl)

	downloads := make(map[string]io.ReadCloser)

	for {
		select {
		case <-cancelCtx.Done():
			if cancelCtx.Err() == context.DeadlineExceeded {
				return nil, fmt.Errorf("was not able to download required content in allowed time")
			}
			return nil, fmt.Errorf("operation was canceled")
		case dl := <-downloadc:
			downloads[dl.resType] = dl.resp.Body
			if len(downloads) == 2 {
				go d.readContent(cancelCtx, downloads, results, maxbytes)
			}
		case result := <-results:
			return result.content, result.err
		}
	}

}

type contextReader struct {
	R   io.Reader
	ctx context.Context
	N   int
}

func (cr *contextReader) Read(p []byte) (n int, err error) {
	if cr.ctx.Err() != nil {
		return 0, io.EOF
	}
	n, err = cr.R.Read(p)
	cr.N += n
	return
}

func (d *downloader) readContent(ctx context.Context, downloads map[string]io.ReadCloser, results chan result, maxbytes int) {

	defer downloads[resContent].Close()
	defer downloads[resSig].Close()

	pr, pw := io.Pipe()
	names := make([]string, 0, 1)

	go func() {
		b, err := ioutil.ReadAll(pr)
		if err != nil {
			results <- result{err: fmt.Errorf("unable to read signed content: %v", err)}
			return
		}
		results <- result{content: &SignedContent{Content: b, Signers: names}}
	}()

	cr := &contextReader{
		R:   io.TeeReader(io.LimitReader(downloads[resContent], int64(maxbytes)), pw),
		ctx: ctx,
	}
	sr := &contextReader{
		R:   io.LimitReader(downloads[resSig], int64(maxbytes)),
		ctx: ctx,
	}

	entity, err := openpgp.CheckArmoredDetachedSignature(d.keyring, cr, sr)

	if err != nil {
		if cr.N >= maxbytes || sr.N >= maxbytes {
			err = fmt.Errorf("reached max bytes allowed to download: %d", maxbytes)
		} else {
			err = fmt.Errorf("file and signature mismatch: %v", err)
		}
		results <- result{err: err}
		pw.CloseWithError(err)
		return
	}
	for _, v := range entity.Identities {
		if v.UserId != nil {
			names = append(names, v.UserId.Name)
		}
	}
	pw.Close()

}
