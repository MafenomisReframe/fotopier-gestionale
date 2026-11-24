# Foto Pier – Gestionale matrimoni

App su Cloudflare Workers + D1. Accesso protetto da Cloudflare Access (solo email autorizzate).

## Struttura
- `public/index.html` – l'app
- `public/shim.js` – collega l'app al database
- `src/worker.js` – API (`/api/all`, `/api/doc`, `/api/calendar`)
- `schema.sql`, `seed.sql` – database (già caricato)
- `wrangler.jsonc` – configurazione

## 1. Pubblicazione
1. Cloudflare → Workers & Pages → Create → Import a repository → scegli `fotopier-gestionale`.
2. Deploy command: `npx wrangler deploy`.
3. Il database D1 `fotopier-gestionale` è già collegato da `wrangler.jsonc`.

## 2. Accesso solo a email autorizzate
1. Cloudflare → Zero Trust → Access → Applications → Add → Self-hosted.
2. Dominio: quello del Worker (`fotopier-gestionale.<account>.workers.dev`).
3. Policy Allow → Emails: le email autorizzate (tu, Pier, weddingfotopier@gmail.com).
4. Copia **Application Audience (AUD) tag** e il **team name** e inseriscili in `wrangler.jsonc`:
   `ACCESS_AUD`, `ACCESS_TEAM`, `ALLOWED_EMAILS` (lista separata da virgole). Poi nuovo deploy.

## 3. Google Calendar (facoltativo)
1. Google Cloud → nuovo progetto → abilita Google Calendar API.
2. IAM → Service Accounts → crea → Keys → JSON.
3. Condividi il calendario weddingfotopier@gmail.com con l'email del service account (modifica eventi).
4. `npx wrangler secret put GOOGLE_SA_JSON` e incolla tutto il JSON.

Il PDF del contratto non si allega all'evento in automatico.
