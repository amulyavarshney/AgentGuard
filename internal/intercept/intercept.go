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
