package manager

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

type LogEntry struct {
	Time    string            `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

type LogBuffer struct {
	mu      sync.Mutex
	limit   int
	entries []LogEntry
}

func NewLogBuffer(limit int) *LogBuffer {
	if limit <= 0 {
		limit = 300
	}
	return &LogBuffer{limit: limit}
}

func (b *LogBuffer) Handler() slog.Handler {
	return &memoryLogHandler{buffer: b}
}

func (b *LogBuffer) Entries() []LogEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	entries := make([]LogEntry, len(b.entries))
	copy(entries, b.entries)
	return entries
}

func (b *LogBuffer) append(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if entry.Time == "" {
		entry.Time = time.Now().Format(time.RFC3339)
	}
	b.entries = append(b.entries, entry)
	if len(b.entries) > b.limit {
		copy(b.entries, b.entries[len(b.entries)-b.limit:])
		b.entries = b.entries[:b.limit]
	}
}

type memoryLogHandler struct {
	buffer *LogBuffer
	attrs  []slog.Attr
	groups []string
}

func (h *memoryLogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return h.buffer != nil
}

func (h *memoryLogHandler) Handle(_ context.Context, record slog.Record) error {
	if h.buffer == nil {
		return nil
	}
	fields := map[string]string{}
	for _, attr := range h.attrs {
		collectLogAttr(fields, h.groups, attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		collectLogAttr(fields, h.groups, attr)
		return true
	})
	entryTime := record.Time
	if entryTime.IsZero() {
		entryTime = time.Now()
	}
	entry := LogEntry{
		Time:    entryTime.Format(time.RFC3339),
		Level:   record.Level.String(),
		Message: record.Message,
		Fields:  fields,
	}
	if len(fields) == 0 {
		entry.Fields = nil
	}
	h.buffer.append(entry)
	return nil
}

func (h *memoryLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &next
}

func (h *memoryLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.groups = append(append([]string{}, h.groups...), name)
	return &next
}

type teeHandler struct {
	handlers []slog.Handler
}

func NewTeeHandler(handlers ...slog.Handler) slog.Handler {
	active := make([]slog.Handler, 0, len(handlers))
	for _, handler := range handlers {
		if handler != nil {
			active = append(active, handler)
		}
	}
	return teeHandler{handlers: active}
}

func (h teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (h teeHandler) Handle(ctx context.Context, record slog.Record) error {
	var joined error
	for _, handler := range h.handlers {
		if !handler.Enabled(ctx, record.Level) {
			continue
		}
		if err := handler.Handle(ctx, record.Clone()); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	return joined
}

func (h teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		handlers = append(handlers, handler.WithAttrs(attrs))
	}
	return teeHandler{handlers: handlers}
}

func (h teeHandler) WithGroup(name string) slog.Handler {
	handlers := make([]slog.Handler, 0, len(h.handlers))
	for _, handler := range h.handlers {
		handlers = append(handlers, handler.WithGroup(name))
	}
	return teeHandler{handlers: handlers}
}

func collectLogAttr(fields map[string]string, groups []string, attr slog.Attr) {
	if attr.Key == "" {
		return
	}
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		nextGroups := append(append([]string{}, groups...), attr.Key)
		for _, child := range value.Group() {
			collectLogAttr(fields, nextGroups, child)
		}
		return
	}
	keyParts := append(append([]string{}, groups...), attr.Key)
	fields[strings.Join(keyParts, ".")] = value.String()
}
