//go:build !light && !no_tftp

package supervisor

import (
	"log/slog"

	"go-fs/internal/service"
	"go-fs/internal/tftp"
)

// The TFTP server, left out by the tag no_tftp and by light.
func init() {
	register(entry{
		name:    "tftp",
		order:   orderTFTP,
		enabled: func(e env) bool { return e.cfg.TFTP.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return tftp.New(e.cfg.TFTP, log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*tftp.Server).Reload(e.cfg.TFTP)
		},
	})
}
