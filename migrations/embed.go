// Package migrations embeds the SQL schema so the binary carries it and can
// migrate its own database at startup.
package migrations

import "embed"

// FS holds every *.up.sql / *.down.sql file in this directory.
//
//go:embed *.sql
var FS embed.FS
