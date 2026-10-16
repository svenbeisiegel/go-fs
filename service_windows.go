package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// serviceName is what the installer registers the service as.
const serviceName = "go-fs"

// start runs go-fs, under the service manager when that is what started it.
// A service has to answer the service manager from its first moments on, or
// it is taken for hung and killed.
func start() error {
	service, err := svc.IsWindowsService()
	if err != nil {
		return err
	}
	if !service {
		return run(nil)
	}
	// a service starts in the system folder; the folder of the executable is
	// where a relative path in the arguments is meant to be found
	if exe, err := os.Executable(); err == nil {
		_ = os.Chdir(filepath.Dir(exe))
	}
	handler := &serviceHandler{}
	if err := svc.Run(serviceName, handler); err != nil {
		return err
	}
	return handler.err
}

// serviceHandler runs go-fs for the service manager and turns its stop and
// shutdown requests into the same shutdown SIGTERM leads to elsewhere.
type serviceHandler struct {
	err error
}

func (h *serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest,
	status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	stop := make(chan struct{})
	var once sync.Once
	done := make(chan error, 1)
	go func() { done <- run(stop) }()

	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			h.err = err
			status <- svc.Status{State: svc.StopPending}
			if errors.Is(err, errRestartService) {
				// the update is in place; ending with an error has the
				// service manager start the service again on it
				h.err = nil
				if err := restartOnFailure(); err != nil {
					fmt.Fprintln(errorOutput, "go-fs: the service may not be restarted:", err)
				}
				return true, 1
			}
			if err != nil {
				// a service specific exit code is a failure to the service
				// manager, which then applies the recovery the installer
				// configured: a restart
				return true, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				status <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				// the shutdown waits for the servers to close, which is
				// worth telling the service manager before it gives up
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				once.Do(func() { close(stop) })
			}
		}
	}
}

// restartOnFailure makes sure the service manager restarts the service when
// it ends with an error, which is how it comes back on an update. The msi
// configures that already; a service set up by hand may have no recovery, or
// apply it to crashes alone.
func restartOnFailure() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()

	actions, err := service.RecoveryActions()
	if err != nil {
		return err
	}
	restarts := false
	for _, action := range actions {
		restarts = restarts || action.Type == mgr.ServiceRestart
	}
	if !restarts {
		restart := mgr.RecoveryAction{Type: mgr.ServiceRestart, Delay: 5 * time.Second}
		// the failure count is reset after a day without one
		if err := service.SetRecoveryActions(
			[]mgr.RecoveryAction{restart, restart, restart}, 24*60*60); err != nil {
			return err
		}
	}
	return service.SetRecoveryActionsOnNonCrashFailures(true)
}
