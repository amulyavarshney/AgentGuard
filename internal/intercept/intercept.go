package intercept

import "context"

// Interceptor wraps agent processes and routes actions through the policy gateway.
type Interceptor interface {
	Wrap(ctx context.Context, opts WrapOptions) error
}

// WrapOptions configures a wrapped agent execution.
type WrapOptions struct {
	Task        string
	Environment string
	Command     []string
	SessionID   string
}

// StubInterceptor is a no-op placeholder kept for tests.
type StubInterceptor struct{}

// Wrap reports that interception is not yet implemented.
func (StubInterceptor) Wrap(_ context.Context, _ WrapOptions) error {
	return ErrNotImplemented
}
