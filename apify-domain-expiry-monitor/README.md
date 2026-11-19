# Domain & SSL Expiry Monitor (Apify Actor)

Checks in bulk when each domain registration expires (official RDAP, public IANA protocol) and when its live TLS certificate expires (port 443 handshake). Returns days left and alert flags (DOMAIN_EXPIRES_SOON, CERT_EXPIRED, CERT_NOT_TRUSTED...).

Who uses it: web agencies, freelancers and IT teams that look after dozens of client domains. An expired domain or certificate takes a site down; checking by hand does not scale.
Only public data (RDAP servers + TLS handshake). No website scraping, so no robots.txt/ToS conflict.

## Input
{ "domains": ["example.com", "https://apify.com/store"], "warnDays": 30, "checkRdap": true, "checkTls": true, "onlyAlerts": false }

Schedule daily with onlyAlerts=true plus a webhook (email/Slack): you only get output (and pay) when something needs attention.

## Output (one row per domain)
domain, alerts[], domainDaysLeft, domainExpires, registrar, nameservers, domainStatus, certDaysLeft, certValidTo, certIssuer, certTrusted, certError, checkedAt

## Pricing (pay-per-event)
Event `domain-checked`: $0.003 per domain (see .actor/pay_per_event.json).
Demand reference (Apify Store API, 19 Nov 2026): agenscrape/whois-domain-lookup 285 users / 187k runs; santamaria-automations/domain-whois-dns 198 / 13k; datascoutapi/DomainDaddy 163 / 178k; SSL checkers 6-25 users each. This Actor combines both with alert flags.

## Test locally
npm install
mkdir -p storage/key_value_stores/default
echo '{"domains":["example.com","github.com","expired.badssl.com"]}' > storage/key_value_stores/default/INPUT.json
APIFY_LOCAL_STORAGE_DIR=./storage node src/main.js
(Results in storage/datasets/default/. Tested on Node 18; Docker image uses Node 20.)

## Publish (commands for the account owner)
npm install -g apify-cli
apify login
cd apify-domain-expiry-monitor
apify push

Then in Apify Console: Actor > Publication > Monetization > Pay per event; add event name `domain-checked`, title "Domain checked", price $0.003. Fill title/description, category Developer tools, make public.

## Notes
- Subdomains fall back to the registrable parent for RDAP (approximate for .co.uk-style TLDs).
- ccTLDs without an RDAP server return RDAP_ERROR; TLS is still checked.
