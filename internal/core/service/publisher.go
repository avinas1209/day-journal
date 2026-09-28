package service

import (
	"context"
	"log/slog"

	"github.com/avinas1209/day-journal/internal/core/domain"
	"github.com/avinas1209/day-journal/internal/core/port"
)

// NopPublisher satisfies port.EventPublisher while messaging is switched off.
// It records each event at debug level so the event stream is still observable
// in logs, and is swapped for the NATS adapter by changing one line in
// cmd/app — no use case is touched.
type NopPublisher struct {
	log *slog.Logger
}

var _ port.EventPublisher = (*NopPublisher)(nil)

func NewNopPublisher(log *slog.Logger) *NopPublisher {
	return &NopPublisher{log: log}
}

func (p *NopPublisher) Publish(ctx context.Context, evt domain.Event) error {
	p.log.DebugContext(ctx, "event dropped (messaging disabled)",
		"event", evt.Name, "entry_id", evt.EntryID)
	return nil
}
