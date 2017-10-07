// Package sigdown uses net/HTTP and add PGP signature verification
package sigdown

import (
	"bytes"
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
	Content string
	Signers []string
}

// Downloader can perform an HTTP download with PGP signature verification
type Downloader struct {
	keyring  openpgp.EntityList
	MaxBytes int
	MaxTime  time.Duration
}

type download struct {
	resType string
	resp    *http.Response
	err     error
}

// New returns new downloader set to verify downloads provided PGP key
func New(pgpPubKey string) (*Downloader, error) {
	d := new(Downloader)
	keyring, err := openpgp.ReadArmoredKeyRing(strings.NewReader(pgpPubKey))
	if err != nil {
		return nil, fmt.Errorf("bad PGP key: %v", err)
	}
	d.keyring = keyring
	d.MaxBytes = 1048576 // 1 MB
	d.MaxTime = 30 * time.Second
	return d, nil
}

// Download fetches data and PGP signature over HTTP and returns data if signed correctly
func (d *Downloader) Download(ctx context.Context, url string, sigurl string) (*SignedContent, error) {

	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeout := time.After(d.MaxTime)

	downloadc := make(chan download)
	downloader := func(name string, url string) {
		req, err := http.NewRequest(http.MethodGet, url, nil)
		req = req.WithContext(cancelCtx)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if err == nil {
				err = fmt.Errorf("unexpected HTTP response code %d", resp.StatusCode)
			}
			downloadc <- download{err: fmt.Errorf("Could not download %s from %s: %v", name, url, err)}
			return
		}
		downloadc <- download{resType: name, resp: resp}
	}

	const (
		resContent = "content"
		resSig     = "signature"
	)

	go downloader(resContent, url)
	go downloader(resSig, sigurl)

	downloads := make(map[string]*http.Response)

	for i := 0; i < 2; i++ {
		select {
		case <-timeout:
			return nil, fmt.Errorf("was not able to download required content in allowed time")
		case <-cancelCtx.Done():
			return nil, fmt.Errorf("operation was canceled")
		case d := <-downloadc:
			if d.err != nil {
				return nil, d.err
			}
			downloads[d.resType] = d.resp
		}
	}

	defer downloads[resContent].Body.Close()
	defer downloads[resSig].Body.Close()

	var buf, sigbuf bytes.Buffer
	maxbytes := d.MaxBytes
	tee := io.TeeReader(io.LimitReader(downloads[resContent].Body, int64(maxbytes)), &buf)
	sigtee := io.TeeReader(io.LimitReader(downloads[resSig].Body, int64(maxbytes)), &sigbuf)

	entity, err := openpgp.CheckArmoredDetachedSignature(d.keyring, tee, sigtee)
	if err != nil {
		if buf.Len() >= maxbytes || sigbuf.Len() >= maxbytes {
			return nil, fmt.Errorf("reached max bytes allowed to download: %d", maxbytes)
		}
		return nil, fmt.Errorf("file and signature mismatch: %v", err)
	}
	sigbuf.Reset()

	names := make([]string, 0, 1)

	for _, v := range entity.Identities {
		if v.UserId != nil {
			names = append(names, v.UserId.Name)
		}
	}

	b, err := ioutil.ReadAll(&buf)
	if err != nil {
		return nil, fmt.Errorf("unable ro read signed content: %v", err)
	}

	return &SignedContent{Content: string(b), Signers: names}, nil

}
