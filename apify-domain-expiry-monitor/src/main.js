import { Actor, log } from 'apify';
import tls from 'node:tls';

async function loadBootstrap() {
    const r = await fetch('https://data.iana.org/rdap/dns.json', { signal: AbortSignal.timeout(15000) });
    const j = await r.json();
    const map = new Map();
    for (const [tlds, urls] of j.services) for (const t of tlds) map.set(t.toLowerCase(), urls.find((u) => u.startsWith('https')) || urls[0]);
    return map;
}

const cleanDomain = (s) => String(s).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '').replace(/^www\./, '').replace(/:\d+$/, '');
const daysLeft = (iso) => (iso ? Math.floor((new Date(iso).getTime() - Date.now()) / 86400000) : null);

async function rdap1(domain, bootstrap) {
    const base = bootstrap.get(domain.split('.').pop());
    if (!base) return { error: 'No RDAP server for this TLD' };
    try {
        const r = await fetch(`${base.replace(/\/$/, '')}/domain/${domain}`, { headers: { accept: 'application/rdap+json' }, signal: AbortSignal.timeout(20000), redirect: 'follow' });
        if (r.status === 404) return { error: 'Domain not registered (RDAP 404)' };
        if (!r.ok) return { error: `RDAP HTTP ${r.status}` };
        const j = await r.json();
        const ev = (a) => (j.events || []).find((e) => e.eventAction === a)?.eventDate || null;
        const reg = (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
        return {
            registrar: reg?.vcardArray?.[1]?.find((x) => x[0] === 'fn')?.[3] || null,
            created: ev('registration'),
            expires: ev('expiration'),
            status: j.status || [],
            nameservers: (j.nameservers || []).map((n) => (n.ldhName || '').toLowerCase()),
        };
    } catch (e) {
        return { error: `RDAP failed: ${e.message}` };
    }
}

async function rdap(domain, bootstrap) {
    let r = await rdap1(domain, bootstrap);
    const parts = domain.split('.');
    if (r.error && /404/.test(r.error) && parts.length > 2) r = await rdap1(parts.slice(-2).join('.'), bootstrap);
    return r;
}

function tlsCheck(domain, port = 443) {
    return new Promise((resolve) => {
        const sock = tls.connect({ host: domain, port, servername: domain, rejectUnauthorized: false, timeout: 10000 }, () => {
            const c = sock.getPeerCertificate();
            const trusted = sock.authorized;
            const trustError = sock.authorizationError || null;
            sock.end();
            if (!c || !c.valid_to) return resolve({ error: 'No certificate' });
            resolve({ issuer: c.issuer?.O || c.issuer?.CN || null, subject: c.subject?.CN || null, validTo: new Date(c.valid_to).toISOString(), trusted, trustError });
        });
        sock.on('timeout', () => { sock.destroy(); resolve({ error: 'TLS timeout' }); });
        sock.on('error', (e) => resolve({ error: `TLS failed: ${e.code || e.message}` }));
    });
}

await Actor.init();
const input = (await Actor.getInput()) || {};
const domains = [...new Set((input.domains || []).map(cleanDomain).filter((d) => d.includes('.')))];
const warnDays = input.warnDays ?? 30;
const checkTls = input.checkTls !== false;
const checkRdap = input.checkRdap !== false;
const onlyAlerts = !!input.onlyAlerts;

if (!domains.length) {
    log.error('Input "domains" is empty. Example: ["example.com","apify.com"]');
    await Actor.fail('No domains provided');
} else {
    const bootstrap = checkRdap ? await loadBootstrap() : new Map();
    let i = 0;
    const worker = async () => {
        while (i < domains.length) {
            const d = domains[i++];
            const [reg, cert] = await Promise.all([checkRdap ? rdap(d, bootstrap) : null, checkTls ? tlsCheck(d) : null]);
            const dDomain = reg?.expires ? daysLeft(reg.expires) : null;
            const dCert = cert?.validTo ? daysLeft(cert.validTo) : null;
            const alerts = [];
            if (dDomain !== null && dDomain < 0) alerts.push('DOMAIN_EXPIRED');
            else if (dDomain !== null && dDomain <= warnDays) alerts.push('DOMAIN_EXPIRES_SOON');
            if (dCert !== null && dCert < 0) alerts.push('CERT_EXPIRED');
            else if (dCert !== null && dCert <= warnDays) alerts.push('CERT_EXPIRES_SOON');
            if (cert && cert.trusted === false) alerts.push('CERT_NOT_TRUSTED');
            if (cert?.error) alerts.push('TLS_ERROR');
            if (reg?.error) alerts.push('RDAP_ERROR');
            if (onlyAlerts && !alerts.length) continue;
            await Actor.pushData({
                domain: d, alerts,
                domainDaysLeft: dDomain, domainExpires: reg?.expires ?? null, registrar: reg?.registrar ?? null,
                domainCreated: reg?.created ?? null, nameservers: reg?.nameservers ?? null, domainStatus: reg?.status ?? null, rdapError: reg?.error ?? null,
                certDaysLeft: dCert, certValidTo: cert?.validTo ?? null, certIssuer: cert?.issuer ?? null, certSubject: cert?.subject ?? null,
                certTrusted: cert?.trusted ?? null, certError: cert?.error ?? cert?.trustError ?? null,
                checkedAt: new Date().toISOString(),
            });
            await Actor.charge({ eventName: 'domain-checked' }).catch(() => {});
        }
    };
    await Promise.all(Array.from({ length: 5 }, worker));
    log.info(`Checked ${domains.length} domains`);
    await Actor.exit();
}
