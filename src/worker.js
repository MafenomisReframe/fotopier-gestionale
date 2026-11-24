/* Gestionale Foto Pier: API per dati (D1) e Google Calendar.
   Le pagine sono servite da Cloudflare (public/); tutto /api/* passa da qui. */

const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
const b64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '=')), c => c.charCodeAt(0));
const PATH_OK = /^(matrimoni\/[A-Za-z0-9_-]{1,40}|impostazioni\/[A-Za-z0-9_-]{1,40})$/;

/* ---- accesso: Cloudflare Access firma ogni richiesta con un JWT ---- */
let jwks = null, jwksAt = 0;
async function accessEmail(req, env) {
  const tok = req.headers.get('Cf-Access-Jwt-Assertion');
  if (!tok || !env.ACCESS_TEAM || !env.ACCESS_AUD) return null;
  const [h, p, s] = tok.split('.');
  if (!h || !p || !s) return null;
  const head = JSON.parse(new TextDecoder().decode(b64u(h)));
  const pay = JSON.parse(new TextDecoder().decode(b64u(p)));
  if (!jwks || Date.now() - jwksAt > 3600e3) {
    const r = await fetch(`https://${env.ACCESS_TEAM}.cloudflareaccess.com/cdn-cgi/access/certs`);
    jwks = (await r.json()).keys; jwksAt = Date.now();
  }
  const jwk = jwks.find(k => k.kid === head.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(s), new TextEncoder().encode(h + '.' + p));
  if (!ok) return null;
  const aud = Array.isArray(pay.aud) ? pay.aud : [pay.aud];
  if (!aud.includes(env.ACCESS_AUD) || pay.exp * 1000 < Date.now()) return null;
  if (env.ALLOWED_EMAILS) {
    const list = env.ALLOWED_EMAILS.toLowerCase().split(/[\s,;]+/).filter(Boolean);
    if (!list.includes(String(pay.email || '').toLowerCase())) return null;
  }
  return pay.email || 'utente';
}

/* ---- Google Calendar con service account ---- */
let gTok = null, gExp = 0;
async function googleToken(env) {
  if (gTok && Date.now() < gExp - 60e3) return gTok;
  const sa = JSON.parse(env.GOOGLE_SA_JSON);
  const now = Math.floor(Date.now() / 1000);
  const enc = (o) => btoa(JSON.stringify(o)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const unsigned = enc({ alg: 'RS256', typ: 'JWT' }) + '.' + enc({ iss: sa.client_email, scope: 'https://www.googleapis.com/auth/calendar', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 });
  const pem = sa.private_key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const key = await crypto.subtle.importKey('pkcs8', Uint8Array.from(atob(pem), c => c.charCodeAt(0)), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(unsigned)));
  let bin = ''; sig.forEach(b => bin += String.fromCharCode(b));
  const jwt = unsigned + '.' + btoa(bin).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=' + jwt });
  const t = await r.json();
  if (!t.access_token) throw new Error('Google: ' + (t.error_description || t.error || 'token non ottenuto'));
  gTok = t.access_token; gExp = Date.now() + (t.expires_in || 3600) * 1000;
  return gTok;
}
async function calendar(env, tool, input) {
  if (!env.GOOGLE_SA_JSON) return json({ error: 'Google Calendar non configurato' }, 501);
  if (tool !== 'create_event' && tool !== 'update_event' && tool !== 'delete_event') return json({ error: 'Operazione non consentita' }, 400);
  const calId = input.calendarId || env.CALENDAR_ID;
  if (tool === 'delete_event') {
    if (!calId || !input.eventId) return json({ error: 'eventId mancante' }, 400);
    const tk = await googleToken(env);
    const dr = await fetch('https://www.googleapis.com/calendar/v3/calendars/' + encodeURIComponent(calId) + '/events/' + encodeURIComponent(input.eventId) + '?sendUpdates=none', { method: 'DELETE', headers: { Authorization: 'Bearer ' + tk } });
    if (!dr.ok && dr.status !== 404 && dr.status !== 410) { let m = 'Errore Google'; try { const j = await dr.json(); m = (j.error && j.error.message) || m; } catch (e) {} return json({ error: m, code: dr.status }, 502); }
    return json({ payload: { deleted: true } });
  }
  if (!calId || typeof input.summary !== 'string' && tool === 'create_event') return json({ error: 'Dati evento mancanti' }, 400);
  const body = {};
  if (input.summary !== undefined) body.summary = String(input.summary).slice(0, 300);
  if (input.description !== undefined) body.description = String(input.description).slice(0, 8000);
  if (input.location !== undefined) body.location = String(input.location).slice(0, 300);
  if (input.colorId) body.colorId = String(input.colorId);
  if (input.startTime && input.endTime) {
    if (input.allDay) { body.start = { date: input.startTime.slice(0, 10) }; body.end = { date: input.endTime.slice(0, 10) }; }
    else { body.start = { dateTime: input.startTime, timeZone: 'Europe/Rome' }; body.end = { dateTime: input.endTime, timeZone: 'Europe/Rome' }; }
  }
  const base = 'https://www.googleapis.com/calendar/v3/calendars/' + encodeURIComponent(calId) + '/events';
  const tok = await googleToken(env);
  const upd = tool === 'update_event';
  if (upd && !input.eventId) return json({ error: 'eventId mancante' }, 400);
  const r = await fetch(upd ? base + '/' + encodeURIComponent(input.eventId) : base, { method: upd ? 'PATCH' : 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const ev = await r.json();
  if (!r.ok) return json({ error: (ev.error && ev.error.message) || 'Errore Google', code: r.status }, 502);
  return json({ payload: { id: ev.id, htmlLink: ev.htmlLink } });
}

/* ---- Google Drive (OAuth con refresh token dell'account weddingfotopier) ---- */
async function driveToken(env) {
  if (!env.GOOGLE_OAUTH_CLIENT_ID || !env.GOOGLE_OAUTH_CLIENT_SECRET || !env.GOOGLE_OAUTH_REFRESH_TOKEN) throw new Error('Google Drive non configurato');
  const r = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: env.GOOGLE_OAUTH_CLIENT_ID, client_secret: env.GOOGLE_OAUTH_CLIENT_SECRET, refresh_token: env.GOOGLE_OAUTH_REFRESH_TOKEN, grant_type: 'refresh_token' }) });
  const t = await r.json();
  if (!t.access_token) throw new Error('Drive: ' + (t.error_description || t.error || 'token non ottenuto'));
  return t.access_token;
}
async function driveUpload(env, b) {
  const anno = String(b.anno || '').replace(/\D/g, '');
  if (!/^20\d\d$/.test(anno)) return json({ error: 'Anno non valido' }, 400);
  const nome = String(b.nome || 'Contratto.pdf').replace(/[\\/:*?"<>|]+/g, '_').slice(0, 150);
  if (!b.pdf || b.pdf.length > 12e6) return json({ error: 'PDF mancante o troppo grande' }, 400);
  const tok = await driveToken(env);
  const H = { Authorization: 'Bearer ' + tok };
  const fname = 'CONTRATTI ' + anno;
  const q = "name='" + fname + "' and mimeType='application/vnd.google-apps.folder' and 'root' in parents and trashed=false";
  let r = await fetch('https://www.googleapis.com/drive/v3/files?fields=files(id)&q=' + encodeURIComponent(q), { headers: H });
  let j = await r.json();
  if (!r.ok) return json({ error: (j.error && j.error.message) || 'Errore Drive', code: r.status }, 502);
  let folder = j.files && j.files[0] && j.files[0].id;
  if (!folder) {
    r = await fetch('https://www.googleapis.com/drive/v3/files?fields=id', { method: 'POST', headers: { ...H, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: fname, mimeType: 'application/vnd.google-apps.folder', parents: ['root'] }) });
    j = await r.json();
    if (!r.ok) return json({ error: (j.error && j.error.message) || 'Errore Drive', code: r.status }, 502);
    folder = j.id;
  }
  const bin = Uint8Array.from(atob(b.pdf), c => c.charCodeAt(0));
  const bd = 'fpb' + Date.now();
  const enc = new TextEncoder();
  const head = enc.encode('--' + bd + '\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n' + JSON.stringify({ name: nome, parents: [folder] }) + '\r\n--' + bd + '\r\nContent-Type: application/pdf\r\n\r\n');
  const tail = enc.encode('\r\n--' + bd + '--');
  const body = new Uint8Array(head.length + bin.length + tail.length);
  body.set(head, 0); body.set(bin, head.length); body.set(tail, head.length + bin.length);
  r = await fetch('https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink', { method: 'POST', headers: { ...H, 'Content-Type': 'multipart/related; boundary=' + bd }, body });
  j = await r.json();
  if (!r.ok) return json({ error: (j.error && j.error.message) || 'Errore Drive', code: r.status }, 502);
  return json({ ok: true, id: j.id, link: j.webViewLink, cartella: fname });
}

async function sendMail(env, b) {
  const to = String(b.to || '').trim();
  if (!/^[^\s@,;<>]+@[^\s@,;<>]+\.[^\s@,;<>]+$/.test(to)) return json({ error: 'Email non valida' }, 400);
  if (b.pdf && b.pdf.length > 12e6) return json({ error: 'PDF troppo grande' }, 400);
  const nome = String(b.nome || 'Contratto.pdf').replace(/[\\/:*?"<>|\r\n]+/g, '_').slice(0, 150);
  const subject = String(b.subject || 'Contratto').replace(/[\r\n]+/g, ' ').slice(0, 200);
  const text = String(b.text || '').slice(0, 5000);
  const enc = new TextEncoder();
  const b64 = (u8) => { let x = ''; for (let i = 0; i < u8.length; i += 32768) x += String.fromCharCode.apply(null, u8.subarray(i, i + 32768)); return btoa(x); };
  const wrap = (t) => t.replace(/(.{76})/g, '$1\r\n');
  const bd = 'fpm' + Date.now();
  const head = ['To: ' + to, 'Subject: =?UTF-8?B?' + b64(enc.encode(subject)) + '?=', 'MIME-Version: 1.0'];
  const mime = b.pdf ? head.concat([
    'Content-Type: multipart/mixed; boundary="' + bd + '"', '', '--' + bd,
    'Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', wrap(b64(enc.encode(text))),
    '--' + bd,
    'Content-Type: application/pdf; name="' + nome + '"', 'Content-Disposition: attachment; filename="' + nome + '"', 'Content-Transfer-Encoding: base64', '', wrap(b.pdf),
    '--' + bd + '--', ''
  ]).join('\r\n') : head.concat(['Content-Type: text/plain; charset=UTF-8', 'Content-Transfer-Encoding: base64', '', wrap(b64(enc.encode(text))), '']).join('\r\n');
  const raw = b64(enc.encode(mime)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const tok = await driveToken(env);
  const r = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/messages/send', { method: 'POST', headers: { Authorization: 'Bearer ' + tok, 'Content-Type': 'application/json' }, body: JSON.stringify({ raw }) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const m = (j.error && j.error.message) || 'Errore Gmail';
    return json({ error: r.status === 403 ? 'Permesso Gmail mancante (serve rifare l\'autorizzazione Google): ' + m : m, code: r.status }, 502);
  }
  return json({ ok: true, id: j.id });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(req);
    try {
      const who = await accessEmail(req, env);
      if (!who) return json({ error: 'Accesso non autorizzato' }, 401);

      if (url.pathname === '/api/all' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT path, data FROM docs').all();
        const docs = {};
        for (const r of results) { try { docs[r.path] = JSON.parse(r.data); } catch (e) {} }
        return json({ docs });
      }
      if (url.pathname === '/api/doc') {
        const path = url.searchParams.get('path') || '';
        if (!PATH_OK.test(path)) return json({ error: 'Percorso non valido' }, 400);
        if (req.method === 'PUT') {
          const txt = await req.text();
          if (txt.length > 300000) return json({ error: 'Documento troppo grande' }, 413);
          JSON.parse(txt);
          await env.DB.prepare('INSERT INTO docs (path, data, updated) VALUES (?1, ?2, ?3) ON CONFLICT(path) DO UPDATE SET data = ?2, updated = ?3').bind(path, txt, Date.now()).run();
          return json({ ok: true });
        }
        if (req.method === 'DELETE') {
          await env.DB.prepare('DELETE FROM docs WHERE path = ?1').bind(path).run();
          return json({ ok: true });
        }
      }
      if (url.pathname === '/api/calendar' && req.method === 'POST') {
        const b = await req.json();
        return await calendar(env, b.tool, b.input || {});
      }
      if (url.pathname === '/api/mail' && req.method === 'POST') return sendMail(env, await req.json());
      if (url.pathname === '/api/drive' && req.method === 'POST') {
        return await driveUpload(env, await req.json());
      }
      return json({ error: 'Non trovato' }, 404);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500);
    }
  }
};
