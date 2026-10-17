//go:build !light && !no_ftp

package supervisor

import (
	"log/slog"

	"go-fs/internal/ftp"
	"go-fs/internal/service"
)

// The FTP and FTPS server, left out by the tag no_ftp and by light.
func init() {
	register(entry{
		name:    "ftp",
		order:   orderFTP,
		enabled: func(e env) bool { return e.cfg.FTP.Enabled || e.cfg.FTPS.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return ftp.New(e.cfg.FTP, e.cfg.FTPS, e.cfg.FTPUsers(), log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*ftp.Server).Reload(e.cfg.FTP, e.cfg.FTPS, e.cfg.FTPUsers())
		},
	})
}
