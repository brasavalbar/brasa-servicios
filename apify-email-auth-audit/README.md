# Email Authentication Audit: SPF, DKIM, DMARC (Apify Actor)

Bulk-audit domains for email authentication using only **public DNS** (no scraping, no login). One row per domain: 0-100 score, issue flags, parsed SPF/DMARC details, MTA-STS and BIMI presence, common DKIM selectors found.

Flags: `SPF_MISSING, SPF_MULTIPLE_RECORDS, SPF_ALLOWS_ALL, SPF_NO_ENFORCEMENT, SPF_OVER_10_LOOKUPS, DMARC_MISSING, DMARC_MONITOR_ONLY, DMARC_NO_REPORTING, DMARC_PARTIAL_PCT`.

Who uses it: agencies, MSPs and deliverability/security consultants checking dozens of client domains (Google and Yahoo require SPF/DKIM/DMARC for bulk senders, so missing records mean mail in spam). Also lead-gen: find prospects with broken email setup.

Market (Apify Store, 20 Nov 2026): andok/dmarc-spf-dkim-validator 6 users, zinin/domain-health-checker 15, ryanclinton/dns-record-lookup 37, all pay-per-event; none combines scoring, SPF lookup counting, DMARC parsing and MTA-STS/BIMI.

Input: `{"domains":["example.com","user@acme.io"],"checkDkim":true}`. Note: DKIM selectors cannot be enumerated; the Actor probes 14 common ones, so "not found" is not proof of absence.

Pricing (pay-per-event): `domain-audited` $0.005 per domain (`.actor/pay_per_event.json`).

Test locally:
```
npm install
mkdir -p storage/key_value_stores/default
echo '{"domains":["google.com","github.com"]}' > storage/key_value_stores/default/INPUT.json
APIFY_LOCAL_STORAGE_DIR=./storage node src/main.js
```
Publish (account owner): `npm i -g apify-cli && apify login && cd apify-email-auth-audit && apify push`, then Console > Publication > Monetization > Pay per event, add event `domain-audited` at $0.005, make public.
