package gate

import (
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/gauntlet"
	"github.com/tomlawesome/gauntlet/persist"
)

// The four hold fields of the account list (#107): lockedUntil,
// disabledUntil, heldSignIn, allowedUntil. Each is present while its
// state holds and absent otherwise, all judged at the gate's clock.

// listRaw is GET /api/auth/users as generic maps by username, so absence
// of a key is visible.
func (e *unusualEnv) listRaw(t *testing.T) map[string]map[string]any {
	t.Helper()
	resp, err := e.adminNow(t).Get(e.ts.URL + "/api/auth/users")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/auth/users = %d", resp.StatusCode)
	}
	var rows []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, r := range rows {
		out[r["username"].(string)] = r
	}
	return out
}

func holdFields(row map[string]any) (present []string) {
	for _, k := range []string{"lockedUntil", "disabledUntil", "heldSignIn", "allowedUntil"} {
		if _, ok := row[k]; ok {
			present = append(present, k)
		}
	}
	return present
}

func requireOnly(t *testing.T, row map[string]any, who string, want ...string) {
	t.Helper()
	got := holdFields(row)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s shows %v, want %v (row %v)", who, got, want, row)
	}
}

func requireTime(t *testing.T, row map[string]any, key string, want time.Time) {
	t.Helper()
	s, _ := row[key].(string)
	got, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || !got.Equal(want) {
		t.Errorf("%s = %q, want %v", key, s, want)
	}
}

func TestAccountListShowsHoldState(t *testing.T) {
	e := newUnusualEnv(t, UnusualSignInPolicy{})
	users := e.g.deps.Users
	mk := func(name string) string {
		t.Helper()
		u, err := users.CreateUser(name, "password-placeholder-"+name, gauntlet.RoleUser, e.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	lockedID, lapsedID, disabledID, heldID, allowedID := mk("locked"), mk("lapsed"), mk("disabled"), mk("held"), mk("allowed")
	mk("plain")

	// disableAccount writes a real disable at a time of its own; the
	// clock is then put an hour after it.
	disableAccount(t, users, disabledID)
	disabledAt := mustUser(t, users, disabledID).LoginDisabledAt
	e.clock.set(disabledAt.Add(time.Hour))
	now := e.clock.now()

	lockedUntil := now.Add(10 * time.Minute)
	if err := users.SetLoginLockedUntil(lockedID, lockedUntil); err != nil {
		t.Fatal(err)
	}
	if err := users.SetLoginLockedUntil(lapsedID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	held := gauntlet.HeldSignIn{At: now.Add(-time.Hour), Outcome: gauntlet.SignInConfirmSent, UserAgent: "Firefox/131.0 (test)", Country: "FR"}
	if err := users.HoldSignIn(heldID, held); err != nil {
		t.Fatal(err)
	}
	if _, err := users.AllowNextSignIn(allowedID, now); err != nil {
		t.Fatal(err)
	}

	rows := e.listRaw(t)
	requireOnly(t, rows["locked"], "locked", "lockedUntil")
	requireTime(t, rows["locked"], "lockedUntil", lockedUntil)
	requireOnly(t, rows["lapsed"], "an account whose lockout lapsed")
	requireOnly(t, rows["plain"], "an untouched account")
	requireOnly(t, rows["admin"], "admin")

	if got := holdFields(rows["disabled"]); !contains(got, "disabledUntil") {
		t.Errorf("a disabled account shows %v, want disabledUntil", got)
	} else {
		requireTime(t, rows["disabled"], "disabledUntil", disabledAt.Add(gauntlet.LoginDisableDuration))
	}

	requireOnly(t, rows["held"], "held", "heldSignIn")
	obj, _ := rows["held"]["heldSignIn"].(map[string]any)
	if obj["outcome"] != "confirm_sent" || obj["userAgent"] != "Firefox/131.0 (test)" || obj["country"] != "FR" {
		t.Errorf("heldSignIn = %v", obj)
	}
	requireTime(t, obj, "at", held.At)

	requireOnly(t, rows["allowed"], "allowed", "allowedUntil")
	requireTime(t, rows["allowed"], "allowedUntil", now.Add(gauntlet.SignInAllowanceLifetime))

	// Later: the disable has run its 24 hours, the allowance has lapsed,
	// the lockout is long over. The hold has no expiry and stays.
	e.clock.set(disabledAt.Add(gauntlet.LoginDisableDuration + time.Second))
	rows = e.listRaw(t)
	if got := holdFields(rows["disabled"]); contains(got, "disabledUntil") {
		t.Errorf("a lapsed disable still shows disabledUntil: %v", rows["disabled"])
	}
	requireOnly(t, rows["locked"], "a lapsed lockout")
	requireOnly(t, rows["allowed"], "a lapsed allowance")
	requireOnly(t, rows["held"], "the held account, much later", "heldSignIn")
}

// The latest hold is cleared by an allowance, so heldSignIn and
// allowedUntil are never both shown.
func TestAccountListNeverShowsHeldAndAllowedTogether(t *testing.T) {
	e, _, _, _ := blockEnvHeld(t)
	requireOnly(t, e.listRaw(t)[totpBobUsername], "bob held", "heldSignIn")
	e.allow(t, e.bobID)
	requireOnly(t, e.listRaw(t)[totpBobUsername], "bob allowed", "allowedUntil")
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func mustUser(t *testing.T, users *gauntlet.Store, id string) *gauntlet.User {
	t.Helper()
	u, ok := users.Get(id)
	if !ok {
		t.Fatalf("account %s is gone", id)
	}
	return u
}

// The list is still one Users.List() call: no per-account read.
func TestAccountListHoldFieldsCostNoPerAccountRead(t *testing.T) {
	backend := &versionCountingBackend{Memory: persist.NewMemory()}
	users := openTrackedStore(t, backend)
	g := newTestGateWithUsers(t, users)
	ts := newTestServer(t, g)
	admin := registerAdmin(t, ts, "admin", "password-placeholder-1")
	get := func() {
		t.Helper()
		resp, err := admin.Get(ts.URL + "/api/auth/users")
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	before := backend.versionCalls.Load()
	get()
	baseline := backend.versionCalls.Load() - before
	for _, name := range []string{"a", "b", "c"} {
		u, err := users.CreateUser(name, "password-placeholder-"+name, gauntlet.RoleUser, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := users.HoldSignIn(u.ID, gauntlet.HeldSignIn{At: time.Now(), Outcome: gauntlet.SignInRefused}); err != nil {
			t.Fatal(err)
		}
		if _, err := users.AllowNextSignIn(u.ID, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := users.SetLoginLockedUntil(u.ID, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	before = backend.versionCalls.Load()
	get()
	if got := backend.versionCalls.Load() - before; got != baseline {
		t.Errorf("the list made %d Version calls with held accounts, want the baseline %d", got, baseline)
	}
}

// The documentation and changelog carry the change.
func TestHoldFieldsAreDocumented(t *testing.T) {
	api, err := os.ReadFile("../docs/api/auth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	documented := schemaPropertyKeys(t, string(api), "UserSummary")
	coded := map[string]bool{}
	rt := reflect.TypeFor[userSummary]()
	for f := range rt.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			t.Fatalf("userSummary.%s has no JSON name; extend this test", f.Name)
		}
		coded[name] = true
	}
	for k := range coded {
		if !documented[k] {
			t.Errorf("userSummary sends %q but docs/api/auth.yaml UserSummary.properties lacks it", k)
		}
	}
	for k := range documented {
		if !coded[k] {
			t.Errorf("docs/api/auth.yaml UserSummary.properties lists %q but userSummary has no such JSON field", k)
		}
	}
	log, err := os.ReadFile("../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "#107") {
		t.Error("CHANGELOG.md has no entry for #107")
	}
}

// schemaPropertyKeys is the set of keys under components.schemas.<name>.properties
// in an OpenAPI document. The root module carries no YAML reader, so this
// reads the block structure by indentation: it is enough for this file's
// two-space mappings, and fails loudly if the schema or its properties
// block is not found.
func schemaPropertyKeys(t *testing.T, doc, name string) map[string]bool {
	t.Helper()
	indentOf := func(l string) int { return len(l) - len(strings.TrimLeft(l, " ")) }
	lines := strings.Split(doc, "\n")
	var i int
	for i = 0; i < len(lines); i++ {
		if lines[i] == "    "+name+":" {
			break
		}
	}
	if i == len(lines) {
		t.Fatalf("schema %s not found in the document", name)
	}
	for i++; i < len(lines); i++ {
		l := lines[i]
		if strings.TrimSpace(l) != "" && indentOf(l) <= 4 {
			t.Fatalf("schema %s has no properties block", name)
		}
		if l == "      properties:" {
			break
		}
	}
	if i == len(lines) {
		t.Fatalf("schema %s has no properties block", name)
	}
	keys := map[string]bool{}
	for i++; i < len(lines); i++ {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		ind := indentOf(l)
		if ind <= 6 {
			break
		}
		if ind == 8 {
			k, _, ok := strings.Cut(trimmed, ":")
			if !ok {
				t.Fatalf("unreadable property line %q", l)
			}
			keys[strings.Trim(k, `"'`)] = true
		}
	}
	if len(keys) == 0 {
		t.Fatalf("schema %s lists no properties", name)
	}
	return keys
}
