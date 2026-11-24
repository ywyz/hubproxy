package handlers

import (
	"errors"
	"io"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"hubproxy/config"
)

const maxAnonymousFileSize int64 = 2 << 30

var errDownloadLoginRequired = errors.New("download exceeds anonymous file size")

func anonymousDownloadLimit() int64 {
	// Older installations can keep their stricter fileSize setting.
	return max(0, min(config.GetConfig().Server.FileSize, maxAnonymousFileSize))
}

type stagedDownload struct {
	*os.File
	size  int64
	quota *directLinkSpoolQuota
}

func (s *stagedDownload) cleanup() {
	_ = s.Close()
	_ = os.Remove(s.Name())
	s.quota.release(s.size)
}

// Stage only when the final size is unknown. A challenge must precede any
// upstream bytes, including the first byte of an anonymously generated tar.
func stageAnonymousDownload(write func(*directLinkQuotaWriter) error) (*stagedDownload, error) {
	file, err := os.CreateTemp("", "hubproxy-download-*")
	if err != nil {
		return nil, err
	}
	staged := &stagedDownload{File: file, quota: directLinkStagingQuota}
	writer := &directLinkQuotaWriter{file: file, quota: staged.quota, limit: anonymousDownloadLimit()}
	ready := false
	defer func() {
		staged.size = writer.reserved
		if !ready {
			staged.cleanup()
		}
	}()
	err = write(writer)
	if writer.err != nil {
		err = writer.err
	}
	if err == nil {
		_, err = file.Seek(0, io.SeekStart)
	}
	if err != nil {
		return nil, err
	}
	ready = true
	return staged, nil
}

func handleDownloadStageError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, errDownloadLoginRequired):
		RequireDownloadLogin(c)
	case errors.Is(err, errDirectLinkSpoolCapacity):
		c.String(http.StatusServiceUnavailable, "下载暂存空间繁忙，请稍后重试")
	default:
		return false
	}
	return true
}
