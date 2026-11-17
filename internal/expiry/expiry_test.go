package expiry

import (
	"testing"
	"time"
)

var issued = time.Date(2026, 10, 9, 12, 0, 0, 123456789, time.UTC)

func TestAtIsIssuedAtPlusLife(t *testing.T) {
	for _, life := range []time.Duration{0, time.Nanosecond, 5 * time.Minute, 24 * time.Hour} {
		if got, want := At(issued, life), issued.Add(life); !got.Equal(want) {
			t.Errorf("At(issued, %v) = %v, want %v", life, got, want)
		}
	}
}

// A ticket is valid only while now is before its expiry (RFC 7519
// section 4.1.4), so the expiry instant itself is already too late.
func TestExpiredIsTrueFromTheExpiryInstant(t *testing.T) {
	const life = 5 * time.Minute
	at := At(issued, life)
	tests := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"at issue", issued, false},
		{"mid-life", issued.Add(life / 2), false},
		{"one nanosecond before the expiry", at.Add(-time.Nanosecond), false},
		{"exactly at the expiry", at, true},
		{"one nanosecond after", at.Add(time.Nanosecond), true},
		{"long after", at.Add(24 * time.Hour), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Expired(issued, life, tc.now); got != tc.want {
				t.Errorf("Expired(issued, %v, %v) = %t, want %t", life, tc.now.Sub(issued), got, tc.want)
			}
		})
	}
}

// A zero life leaves no time at all: the ticket is expired the moment it
// is issued.
func TestZeroLifeIsExpiredAtIssue(t *testing.T) {
	if !Expired(issued, 0, issued) {
		t.Error("Expired(issued, 0, issued) = false, want true")
	}
	if !Expired(issued, 0, issued.Add(time.Second)) {
		t.Error("Expired(issued, 0, issued+1s) = false, want true")
	}
	if !At(issued, 0).Equal(issued) {
		t.Errorf("At(issued, 0) = %v, want issued", At(issued, 0))
	}
}
