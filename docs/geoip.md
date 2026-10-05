# Sign-in country: setting it up

Gauntlet can record which country each sign-in came from, as a
two-letter code such as `GB` on the admin sign-in history and on each
person's session list (#54, [ADR-0008](adr/0008-sign-in-country.md)).
This page is for whoever wires gauntlet into an application and for the
operators who run it.

## How it works

The application runs a `geoip.Manager` and passes its `Country` method
as `gate.Config.Country`. The manager downloads one provider's country
file to your server, keeps it up to date, and looks addresses up in it
there. **No address is ever sent to the provider**; the only request
out is the daily check for a new file.

The country is looked up once, when the sign-in happens, and stored
with it. It is blank when the address is private (a sign-in from your
own network), when no file has been downloaded yet, or when the file
has no entry for the address. A blank country is never filled in later.

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

Gauntlet does not store the key. Keep it the way the application keeps
its other secrets -- a mounted secret file is best -- and pass it in
when the application starts. It never appears in a log line, an error
or `Manager.Status`. If the provider refuses the key, the manager logs
one warning naming the provider and tries again a day later; check the
key and restart.

## Where the file is kept

`Config.Dir` (required) holds the last good file as `maxmind.mmdb` or
`ipinfo.mmdb` (or `maxmind-city.mmdb`, below), and a small `state.json`
saying when it was fetched. The directory is created readable by the
service only (0700), and the files are written 0600. After a restart
the kept file is used straight away, before any download.

**Leave this directory out of backups.** It is the provider's public
data, downloaded again on demand, not your data. It is a few megabytes
for MaxMind's country file and tens of megabytes for IPinfo's; the
city file (below) is roughly ten times its own country file, still
tens of megabytes, well under the manager's 128 MiB download cap.

The manager checks for a new file once a day (`Config.Interval`, no
less than an hour). A failed check keeps the file it has and tries
again in an hour. If the file it has is more than 45 days old, every
check logs a warning, and `Status().Stale` is true, but it is still
used.

The download only ever goes to the provider's own https address. The
default client refuses to follow a redirect to plain http or to any
private or reserved address.

## Locations, for impossible travel

Gauntlet can also judge whether a sign-in travelled further than is
physically possible since the account's last one -- one of the
"unusual sign-in" signals (#55, [ADR-0009](adr/0009-unusual-sign-ins.md)).
This needs a point for each address, not just a country, which only
MaxMind's larger GeoLite2-City file carries.

Set `geoip.Config.Edition` to `geoip.EditionCity` and `Config.Source`
to `geoip.SourceMaxMind` -- IPinfo Lite has no coordinates, so
`New` refuses `EditionCity` with `SourceIPinfo`, and impossible travel
is simply unavailable on that provider. The city file is kept
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

`Manager.Status().Locates` is true once a city file is loaded, so an
application can show whether impossible travel is actually available
yet, the same way it already shows whether a country file is loaded.

Everything above -- the key, the download, the cache directory, the
credit -- works the same way for the city file as for the country
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
  Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0): "The
  attribution requirements can be met by giving our service credit as
  your data source. Simply place a link to IPinfo on the website,
  application, or social media account that uses our data."

These terms are the providers' and can change; read them again before
a release that shows the data somewhere new.

## Checking it is working

`Manager.Status()` reports the source, the edition, whether a file is
loaded, whether it carries locations (`Locates`), when it was fetched,
when the next check is, the last error (if the last check failed) and
whether the file is stale. An application can show it on a health or
settings page; it carries no key.
