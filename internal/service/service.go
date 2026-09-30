// Package service is the vocabulary the supervisor and the servers share.
package service

import (
	"context"
	"errors"
)

// ErrNeedsRestart is what Reload returns for a change that cannot be applied
// to a running server, so that the supervisor tears it down and builds it
// again instead. A port, a base folder or a certificate is such a change: the
// listener has to be rebound.
var ErrNeedsRestart = errors.New("the change needs the server to be restarted")

// Server is what the supervisor holds. Every server in go-fs satisfies it.
type Server interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}
