package hashcost

import "testing"

// Off until a test switches it on, and Use hands back the setting it
// replaced so the caller can restore it.
func TestUseSwitchesAndReportsThePreviousSetting(t *testing.T) {
	if Cheap() {
		t.Fatal("the cheap cost is on before anything asked for it")
	}
	if was := Use(true); was {
		t.Error("Use(true) reported the cheap cost already on")
	}
	if !Cheap() {
		t.Error("Use(true) did not switch the cheap cost on")
	}
	if was := Use(false); !was {
		t.Error("Use(false) did not report the cheap cost as on")
	}
	if Cheap() {
		t.Error("Use(false) did not switch the cheap cost off")
	}
}
