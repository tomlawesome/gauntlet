package gauntlet

import "time"

// HeldSignIn is the latest sign-in on an account that gate's
// unusual-sign-in policy held (#107): every credential right, no session
// issued.
type HeldSignIn struct {
	At        time.Time     `json:"at"`
	Outcome   SignInOutcome `json:"outcome"` // refused | confirm_sent | escape_issued
	UserAgent string        `json:"userAgent,omitempty"`
	Country   string        `json:"country,omitempty"`
}

// HoldSignIn records held as accountID's latest held sign-in (#107),
// replacing any earlier one. UserAgent and Country are cleaned as
// SessionClient.Clean does. Refused with ErrUserNotFound for an account
// that does not exist.
func (s *Store) HoldSignIn(accountID string, held HeldSignIn) error {
	c := SessionClient{UserAgent: held.UserAgent, Country: held.Country}.Clean()
	held.UserAgent, held.Country = c.UserAgent, c.Country
	s.reloadIfStale()
	return s.mutate(func(st *storeState) error {
		u, ok := st.byID[accountID]
		if !ok {
			return ErrUserNotFound
		}
		u.HeldSignIn = &held
		return nil
	})
}
