package intercept

import "errors"

// ErrNotImplemented indicates the interceptor is not yet wired.
var ErrNotImplemented = errors.New("interceptor not implemented")
