# Sign-in country: setting it up

Gauntlet can record which country each sign-in came from, as a
two-letter code such as `GB` on the admin sign-in history and on each
person's session list (#54, [ADR-0008](adr/0008-sign-in-country.md)).
This page is for whoever wires gauntlet into an application and for the
operators who run it.

## How it works

The application runs a `geoip.Manager` and passes its `Country` method
as `gate.Config.Country`. The manager downloads one provider's country
file to your server, keeps it up to date, and looks up the sign-in's IP
address in that file on your own server. **No address is ever sent to
the provider**; the only request out is the daily check for a new file.

Start it with `go m.Run(ctx)` (it checks for a new file at once and
then every `Interval`) and call `m.Close()` after `Run` has returned. Without
`Run`, only a file already in `Config.Dir` is used.

The country is looked up once, when the sign-in happens, and stored
with it. The country is blank when the IP address is private (a sign-in
from your own network), when no file has been downloaded yet, or when
the file has no entry for the address. A blank country stays blank: it
is never filled in later.

Leave `gate.Config.Country` unset and no country is recorded and no
request is made.

## Choosing a provider

Pick **one**. Both are free, and both need an account.

| | MaxMind GeoLite2-Country | IPinfo Lite |
|---|---|---|
| `geoip.Config.Source` | `geoip.SourceMaxMind` | `geoip.SourceIPinfo` |
| Sign up at | [maxmind.com](https://www.maxmind.com) (a free GeoLite account) | [ipinfo.io](https://ipinfo.io/lite) (a free Lite account) |
| What you need | your account ID and a licence key created in that account | your account's access token |
| Goes in | `Config.MaxMind.AccountID`, `Config.MaxMind.LicenceKey` | `Config.IPinfo.Token` |

Where to find them, once signed in:

- **MaxMind**: open the
  [License Keys page](https://www.maxmind.com/en/accounts/current/license-key).
  It shows your account ID, and lets you generate a new licence key.
  The key is shown only once, when it is made, so copy it then.
- **IPinfo**: the access token is shown in your account dashboard.

Gauntlet does not store the key. Keep it the way the application keeps
its other secrets -- a mounted secret file is best -- and pass it in
when the application starts. It never appears in a log line, an error
or `Manager.Status`. If the provider refuses the key, the manager logs
one warning naming the provider and tries again a day later. If the key
is wrong, correct it and restart the application.

## Where the file is kept

Both providers ship their data as an `.mmdb` file: a file listing
network address ranges and what the provider knows about each (the
country, or for MaxMind's city file, an approximate location). You name a folder in `Config.Dir`
(required), and the manager keeps there:

- the last good file, as `maxmind.mmdb` or `ipinfo.mmdb` (or
  `maxmind-city.mmdb`, below);
- a small `state.json` saying when it was fetched.

The manager creates the folder so that only the account the application
runs as can open it (permissions 0700), and the files likewise (0600). After a restart the kept file is used
straight away, before any download.

**Leave the `Config.Dir` folder out of backups.** It holds only the
provider's public data, which the manager downloads again when needed,
not your data.
Expect a few MB for MaxMind's country file, and tens of MB for IPinfo's
and for MaxMind's city file. Gauntlet refuses any download over
128 MiB.

The manager checks for a new file once a day (`Config.Interval`, no
less than an hour). A failed check keeps the file it has and tries
again in an hour. If the file it has is more than 45 days old, every
check logs a warning, and `Status().Stale` is true, but it is still
used.

The download only goes to the provider's own secure (https) web
address. The built-in downloader will not follow a forwarding link
(redirect) to an unencrypted `http` address. It also refuses to connect
to any address on your own network or any other non-public address,
redirects included. So a hijacked download link cannot reach your
internal systems.

## Locations, for spotting sign-ins from too far apart

Gauntlet can also judge whether a sign-in travelled further than is
physically possible since the account's last one -- one of the
"unusual sign-in" signals (#55, [ADR-0009](adr/0009-unusual-sign-ins.md)).
This needs the approximate latitude and longitude of each address,
not just its country. Only MaxMind's larger GeoLite2-City file contains
them.

Set `geoip.Config.Edition` to `geoip.EditionCity` and `Config.Source`
to `geoip.SourceMaxMind` -- IPinfo Lite has no coordinates, so
choosing the city file with IPinfo is an error (`New` refuses it), and
this check cannot be used with IPinfo. The city file is kept
separately, as `maxmind-city.mmdb`, so switching back to the country
file does not lose it; delete whichever edition's file you are no
longer using.

Pass the manager's `Locate` method as `gate.Config.Locate`, alongside
`Country`:

```go
m, err := geoip.New(geoip.Config{
    Source:  geoip.SourceMaxMind,
    Edition: geoip.EditionCity,
    MaxMind: geoip.MaxMindKey{AccountID: accountID, LicenceKey: licenceKey},
    Dir:     dir,
})
// ...
cfg := gate.Config{
    Country: m.Country,
    Locate:  m.Locate,
    // UnusualSignIns: ... (ADR-0009)
}
```

`Manager.Status().Locates` becomes true once the city file has loaded,
so an application can show whether the too-far-apart check is working
yet, the same way it already shows whether a country file is loaded.

Everything above -- the key, the download, the `Config.Dir` folder,
the credit -- works the same way for the city file as for the country
file; only the edition and the file name differ.

## Credit the provider

**Both providers ask the application that uses their data to credit
them.** Gauntlet is a library with no page of its own, so this is the
application's job: put the credit wherever it shows the country, or on
its About page.

What each provider asks for, as checked on 2026-10-04:

- **MaxMind**, [GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula)
  (updated 12 February 2026), section 3: "You must provide attribution
  of your use to MaxMind (an example of attribution: 'This product
  includes GeoLite Data created by MaxMind, available from
  https://www.maxmind.com'.)"
- **IPinfo**, [IPinfo Lite](https://ipinfo.io/lite), licensed under
  Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0). The licence
  requires credit to IPinfo; IPinfo says a link to IPinfo on the website
  or application that uses the data is enough. IPinfo's own words: "The
  attribution requirements can be met by giving our service credit as
  your data source. Simply place a link to IPinfo on the website,
  application, or social media account that uses our data."

These terms are the providers' and can change; read them again before
a release that shows the data somewhere new.

## Checking it is working

`Manager.Status()` reports the source, the edition, whether a file is
loaded, whether it carries locations (`Locates`), when it was fetched,
when the next check is, the last error (if the last check failed) and
whether the file is out of date (over 45 days old). An application can show it on a health or
settings page; it carries no key.
