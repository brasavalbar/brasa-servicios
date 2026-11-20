import { Actor, log } from 'apify';
import dns from 'node:dns/promises';

const clean = (s) => String(s).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^.*@/, '').replace(/[/?#].*$/, '').replace(/^www\./, '');
const txt = async (name) => {
    try { return (await dns.resolveTxt(name)).map((a) => a.join('')); } catch (e) { return e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? [] : null; }
};
const parseTags = (s) => Object.fromEntries(s.split(';').map((x) => x.trim()).filter(Boolean).map((x) => { const i = x.indexOf('='); return [x.slice(0, i).trim().toLowerCase(), x.slice(i + 1).trim()]; }));

async function spfLookups(domain, seen = new Set(), depth = 0) {
    if (seen.has(domain) || depth > 10) return 0;
    seen.add(domain);
    const rec = ((await txt(domain)) || []).find((r) => /^v=spf1\b/i.test(r));
    if (!rec) return 0;
    let n = 0;
    for (const t of rec.split(/\s+/).slice(1)) {
        const m = t.replace(/^[+\-~?]/, '');
        if (/^(include:|redirect=)/i.test(m)) { n++; n += await spfLookups(m.split(/[:=]/)[1], seen, depth + 1); }
        else if (/^(a|mx|ptr|exists)([:/]|$)/i.test(m)) n++;
    }
    return n;
}

const SELECTORS = ['default', 'google', 'selector1', 'selector2', 's1', 's2', 'k1', 'k2', 'mail', 'dkim', 'mandrill', 'smtp', 'mxvault', 'zoho'];

async function audit(domain, checkDkim) {
    const issues = [];
    const mx = await dns.resolveMx(domain).then((r) => r.sort((a, b) => a.priority - b.priority).map((x) => x.exchange)).catch(() => []);
    // SPF
    const all = (await txt(domain)) || [];
    const spfs = all.filter((r) => /^v=spf1\b/i.test(r));
    let spf = { present: spfs.length > 0, record: spfs[0] || null, policy: null, lookups: null };
    if (spfs.length > 1) issues.push('SPF_MULTIPLE_RECORDS');
    if (!spfs.length) issues.push('SPF_MISSING');
    else {
        const m = spfs[0].match(/\s([+\-~?])all\b/i);
        spf.policy = m ? ({ '-': 'fail', '~': 'softfail', '?': 'neutral', '+': 'pass(open!)' })[m[1]] : (/redirect=/i.test(spfs[0]) ? 'redirect' : 'none');
        if (spf.policy === 'pass(open!)') issues.push('SPF_ALLOWS_ALL');
        if (spf.policy === 'neutral' || spf.policy === 'none') issues.push('SPF_NO_ENFORCEMENT');
        spf.lookups = await spfLookups(domain);
        if (spf.lookups > 10) issues.push('SPF_OVER_10_LOOKUPS');
    }
    // DMARC
    const dm = ((await txt(`_dmarc.${domain}`)) || []).find((r) => /^v=DMARC1/i.test(r));
    let dmarc = { present: !!dm, record: dm || null, policy: null, pct: null, rua: null };
    if (!dm) issues.push('DMARC_MISSING');
    else {
        const t = parseTags(dm);
        dmarc = { ...dmarc, policy: t.p || null, subdomainPolicy: t.sp || null, pct: t.pct ? Number(t.pct) : 100, rua: t.rua || null };
        if (t.p === 'none') issues.push('DMARC_MONITOR_ONLY');
        if (!t.rua) issues.push('DMARC_NO_REPORTING');
        if (t.pct && Number(t.pct) < 100) issues.push('DMARC_PARTIAL_PCT');
    }
    // MTA-STS, BIMI
    const mtasts = ((await txt(`_mta-sts.${domain}`)) || []).some((r) => /^v=STSv1/i.test(r));
    const bimi = ((await txt(`default._bimi.${domain}`)) || []).some((r) => /^v=BIMI1/i.test(r));
    // DKIM (common selectors only)
    let dkimSelectors = null;
    if (checkDkim) {
        dkimSelectors = [];
        for (const s of SELECTORS) {
            const r = await dns.resolveCname(`${s}._domainkey.${domain}`).then(() => true).catch(() => null);
            const t = r || ((await txt(`${s}._domainkey.${domain}`)) || []).some((x) => /p=[A-Za-z0-9+\/]{20,}/.test(x));
            if (t) dkimSelectors.push(s);
        }
    }
    let score = 100;
    const pen = { SPF_MISSING: 25, SPF_MULTIPLE_RECORDS: 20, SPF_ALLOWS_ALL: 30, SPF_NO_ENFORCEMENT: 10, SPF_OVER_10_LOOKUPS: 15, DMARC_MISSING: 35, DMARC_MONITOR_ONLY: 15, DMARC_NO_REPORTING: 5, DMARC_PARTIAL_PCT: 5 };
    for (const i of issues) score -= pen[i] || 0;
    return { domain, score: Math.max(0, score), issues, hasMx: mx.length > 0, mx, spf, dmarc, mtaSts: mtasts, bimi, dkimSelectorsFound: dkimSelectors, checkedAt: new Date().toISOString() };
}

await Actor.init();
const input = (await Actor.getInput()) || {};
const domains = [...new Set((input.domains || []).map(clean).filter((d) => d.includes('.')))];
if (!domains.length) { log.error('Input "domains" is empty.'); await Actor.fail('No domains provided'); }
else {
    let i = 0;
    const worker = async () => {
        while (i < domains.length) {
            const d = domains[i++];
            const row = await audit(d, input.checkDkim !== false);
            await Actor.pushData(row);
            await Actor.charge({ eventName: 'domain-audited' }).catch(() => {});
        }
    };
    await Promise.all(Array.from({ length: 5 }, worker));
    log.info(`Audited ${domains.length} domains`);
    await Actor.exit();
}
