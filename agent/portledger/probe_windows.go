//go:build windows

package portledger

import (
	"errors"
	"syscall"
)

const (
	wsaEACCES     syscall.Errno = 10013
	wsaEADDRINUSE syscall.Errno = 10048
)

func isAddrInUse(err error) bool {
	return errors.Is(err, wsaEADDRINUSE) || errors.Is(err, syscall.EADDRINUSE)
}

func isPermission(err error) bool {
	return errors.Is(err, wsaEACCES) || errors.Is(err, syscall.EACCES)
}
