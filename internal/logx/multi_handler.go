package logx

import (
	"context"
	"io"
	"log/slog"
)

// multiHandler 将日志同时写入多个 handler
type multiHandler struct {
	handlers []slog.Handler
}

func newMultiWriterHandler(writers []io.Writer, opts *slog.HandlerOptions, textMode bool) *multiHandler {
	h := &multiHandler{}
	for _, w := range writers {
		if textMode {
			h.handlers = append(h.handlers, slog.NewTextHandler(w, opts))
		} else {
			h.handlers = append(h.handlers, slog.NewJSONHandler(w, opts))
		}
	}
	return h
}

func (h *multiHandler) Enabled(_ context.Context, level slog.Level) bool {
	if len(h.handlers) == 0 {
		return false
	}
	return h.handlers[0].Enabled(context.Background(), level)
}

func (h *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			handler.Handle(ctx, r)
		}
	}
	return nil
}

func (h *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithAttrs(attrs)
	}
	return &multiHandler{handlers: newHandlers}
}

func (h *multiHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithGroup(name)
	}
	return &multiHandler{handlers: newHandlers}
}
