//go:build !light && !no_sftpd

package supervisor

import (
	"log/slog"

	"go-fs/internal/service"
	"go-fs/internal/sftp"
)

// The SFTP server, left out by the tag no_sftpd and by light.
func init() {
	register(entry{
		name:    "sftp",
		order:   orderSFTP,
		enabled: func(e env) bool { return e.cfg.SFTP.Enabled },
		create: func(e env, log *slog.Logger) (service.Server, error) {
			return sftp.New(e.cfg.SFTP, e.cfg.General.SSH, e.cfg.SFTPUsers(), log)
		},
		reload: func(s service.Server, e env) error {
			return s.(*sftp.Server).Reload(e.cfg.SFTP, e.cfg.General.SSH, e.cfg.SFTPUsers())
		},
	})
}
