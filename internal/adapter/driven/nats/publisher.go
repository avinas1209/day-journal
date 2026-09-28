// Package nats is a driven adapter that implements port.EventPublisher on top
// of NATS JetStream.
//
// PARKED — messaging is not switched on yet, so the whole implementation is
// commented out and cmd/app wires service.NopPublisher instead. The nats.go
// dependency is kept in go.mod so that restoring this file is a matter of
// uncommenting it and swapping the publisher back in main.go; nothing in the
// core changes, because the core only ever sees port.EventPublisher.
package nats

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"time"
//
// 	"github.com/nats-io/nats.go"
// 	"github.com/nats-io/nats.go/jetstream"
//
// 	"github.com/avinas1209/day-journal/internal/core/domain"
// 	"github.com/avinas1209/day-journal/internal/core/port"
// )
//
// type Config struct {
// 	URL            string
// 	StreamName     string
// 	SubjectPrefix  string
// 	ConnectTimeout time.Duration
// }
//
// // Connect dials NATS and ensures the stream the publisher writes into exists.
// func Connect(ctx context.Context, cfg Config) (*nats.Conn, jetstream.JetStream, error) {
// 	conn, err := nats.Connect(cfg.URL,
// 		nats.Timeout(cfg.ConnectTimeout),
// 		nats.MaxReconnects(-1),
// 		nats.ReconnectWait(2*time.Second),
// 	)
// 	if err != nil {
// 		return nil, nil, fmt.Errorf("nats: connect: %w", err)
// 	}
//
// 	js, err := jetstream.New(conn)
// 	if err != nil {
// 		conn.Close()
// 		return nil, nil, fmt.Errorf("nats: jetstream: %w", err)
// 	}
//
// 	ctx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
// 	defer cancel()
//
// 	_, err = js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
// 		Name:     cfg.StreamName,
// 		Subjects: []string{cfg.SubjectPrefix + ".>"},
// 		Storage:  jetstream.FileStorage,
// 	})
// 	if err != nil {
// 		conn.Close()
// 		return nil, nil, fmt.Errorf("nats: create stream: %w", err)
// 	}
// 	return conn, js, nil
// }
//
// // EventPublisher implements port.EventPublisher.
// type EventPublisher struct {
// 	js     jetstream.JetStream
// 	prefix string
// }
//
// var _ port.EventPublisher = (*EventPublisher)(nil)
//
// func NewEventPublisher(js jetstream.JetStream, subjectPrefix string) *EventPublisher {
// 	return &EventPublisher{js: js, prefix: subjectPrefix}
// }
//
// func (p *EventPublisher) Publish(ctx context.Context, evt domain.Event) error {
// 	payload, err := json.Marshal(evt)
// 	if err != nil {
// 		return fmt.Errorf("nats: encode event: %w", err)
// 	}
// 	subject := p.prefix + "." + evt.Name
// 	// MsgId lets JetStream de-duplicate if the caller retries.
// 	if _, err := p.js.Publish(ctx, subject, payload, jetstream.WithMsgID(evt.ID.String())); err != nil {
// 		return fmt.Errorf("nats: publish %s: %w", subject, err)
// 	}
// 	return nil
// }
//
