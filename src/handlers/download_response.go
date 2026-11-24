package handlers

import (
	"errors"
	"io"
	"net/http"
	"time"
)

const (
	downloadWriteIdle = 2 * time.Minute
	downloadBlockSize = 32 * 1024
)

type idleDownloadWriter struct {
	dst        http.ResponseWriter
	controller *http.ResponseController
}

func downloadResponseWriter(w http.ResponseWriter) io.Writer {
	return &idleDownloadWriter{dst: w, controller: http.NewResponseController(w)}
}

func (w *idleDownloadWriter) Write(p []byte) (int, error) {
	var written int
	for len(p) > 0 {
		if w.controller != nil {
			err := w.controller.SetWriteDeadline(time.Now().Add(downloadWriteIdle))
			if errors.Is(err, http.ErrNotSupported) {
				w.controller = nil // e.g. an in-memory httptest.ResponseRecorder
			} else if err != nil {
				return written, err
			}
		}
		block := p[:min(len(p), downloadBlockSize)]
		n, err := w.dst.Write(block)
		written += n
		if err != nil {
			return written, err
		}
		if n != len(block) {
			return written, io.ErrShortWrite
		}
		p = p[n:]
	}
	// net/http flushes its buffered tail after the handler returns. Keep the
	// last deadline in place for that flush; net/http resets it for reuse.
	return written, nil
}

func copyDownloadResponse(w http.ResponseWriter, src io.Reader) (int64, error) {
	// Hide WriterTo on files and in-memory readers so io.Copy uses bounded reads.
	return io.Copy(downloadResponseWriter(w), struct{ io.Reader }{src})
}
