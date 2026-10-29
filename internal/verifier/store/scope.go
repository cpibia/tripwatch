package store

import "context"

type scopeKey struct{}

// WithScope narrows what the store returns, for the request of a user who may see only the
// servers carrying a label: their hosts, their alerts and their events. Every query of hosts,
// alerts and events reads it from the context, so a page cannot forget it. An empty label sees
// everything, as the verifier's own work does.
func WithScope(ctx context.Context, label string) context.Context {
	if label == "" {
		return ctx
	}
	return context.WithValue(ctx, scopeKey{}, label)
}

// scopeClause is the condition, joined with AND, that keeps the rows of the hosts in the
// context's scope, with its argument; empty when the context has none.
func scopeClause(ctx context.Context, column string) (string, []any) {
	label, _ := ctx.Value(scopeKey{}).(string)
	if label == "" {
		return "", nil
	}
	return ` AND ` + column + ` IN (SELECT id FROM hosts WHERE instr(char(10) || labels || char(10), char(10) || ? || char(10)) > 0)`, []any{label}
}
