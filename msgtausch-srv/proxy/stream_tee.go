package proxy

import (
	"io"
)

// teeReadCloser wraps an io.ReadCloser and calls cb with each chunk read.
// If cb returns an error, subsequent reads will propagate that error.
type teeReadCloser struct {
	rc  io.ReadCloser
	cb  func([]byte) error
	err error
}

func newTeeReadCloser(rc io.ReadCloser, cb func([]byte) error) io.ReadCloser {
	return &teeReadCloser{rc: rc, cb: cb}
}

func (t *teeReadCloser) Read(p []byte) (int, error) {
	if t.err != nil {
		return 0, t.err
	}
	n, err := t.rc.Read(p)
	if n > 0 && t.cb != nil {
		if cbErr := t.cb(p[:n]); cbErr != nil && t.err == nil {
			// Capture the first callback error to stop further processing
			t.err = cbErr
			return n, cbErr
		}
	}
	return n, err
}

func (t *teeReadCloser) Close() error {
	return t.rc.Close()
}
