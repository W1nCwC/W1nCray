package filesync

import (
	"context"

	"github.com/W1nCwC/W1nCray/agent/spec"
)

// FileRef is one managed file of the desired state; it is spec.FileRef, named
// here so the filesync API reads in terms of files.
type FileRef = spec.FileRef

// Validator pre-checks a staged file set before anything is replaced. It is
// implemented by the panel (which owns the live instance options) so the check
// uses the same xray kernel and the same config loader the running instance
// does; tests substitute a fake.
//
// ValidateStaged returns one error per problem, with the file name and, where
// the kernel knows it, the entry index (design section 3.4 step 3). An empty
// result means the staged set is good.
type Validator interface {
	ValidateStaged(ctx context.Context, dir string, files []FileRef) []error
}

// ValidatorFunc adapts a function to Validator.
type ValidatorFunc func(ctx context.Context, dir string, files []FileRef) []error

// ValidateStaged implements Validator.
func (f ValidatorFunc) ValidateStaged(ctx context.Context, dir string, files []FileRef) []error {
	return f(ctx, dir, files)
}
