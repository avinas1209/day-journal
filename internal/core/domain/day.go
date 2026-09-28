package domain

import "time"

const dayLayout = "2006-01-02"

// Day is a calendar date with no time or zone component. Journaling is a
// per-day activity, so the domain models the day itself rather than an instant.
type Day struct {
	t time.Time // always UTC midnight
}

func NewDay(year int, month time.Month, dayOfMonth int) Day {
	return Day{t: time.Date(year, month, dayOfMonth, 0, 0, 0, 0, time.UTC)}
}

// ParseDay reads the ISO-8601 form, "2025-01-31".
func ParseDay(s string) (Day, error) {
	t, err := time.Parse(dayLayout, s)
	if err != nil {
		return Day{}, ValidationError{Field: "day", Reason: "must look like YYYY-MM-DD"}
	}
	return Day{t: t.UTC()}, nil
}

// DayFromTime truncates an instant to its UTC calendar date.
func DayFromTime(t time.Time) Day {
	t = t.UTC()
	return NewDay(t.Year(), t.Month(), t.Day())
}

func Today() Day { return DayFromTime(time.Now()) }

func (d Day) Time() time.Time  { return d.t }
func (d Day) String() string   { return d.t.Format(dayLayout) }
func (d Day) IsZero() bool     { return d.t.IsZero() }
func (d Day) After(o Day) bool { return d.t.After(o.t) }

// Start and End bound the day as an instant range, half-open: [Start, End).
// Repositories filter timestamps with these rather than casting columns, so
// an index on the timestamp column stays usable.
func (d Day) Start() time.Time { return d.t }
func (d Day) End() time.Time   { return d.t.AddDate(0, 0, 1) }

func (d Day) AddDays(n int) Day {
	return Day{t: d.t.AddDate(0, 0, n)}
}
