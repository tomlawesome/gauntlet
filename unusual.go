package gauntlet

// Location is a point and how far around it an address is likely to
// be, as a city-level lookup gives it (geoip's EditionCity). It is what
// impossible travel compares (#55); a sign-in's country is enough for
// everything else.
type Location struct {
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	// RadiusKm is the lookup's accuracy radius: the address is likely
	// within this many kilometres of the point.
	RadiusKm int `json:"radiusKm"`
}
