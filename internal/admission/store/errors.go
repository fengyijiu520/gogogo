package store

import (
	"errors"
	"os"
)

var ErrNotFound = errors.New("not found")

func errFileNotExist() error {
	return os.ErrNotExist
}
