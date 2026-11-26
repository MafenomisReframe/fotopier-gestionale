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

## 2. Accesso con password
L'app chiede la sua password (sessione di 30 giorni sul dispositivo, poi la richiede di nuovo). Non serve Cloudflare Access:
se esiste un'applicazione Access per questo Worker, va eliminata (Zero Trust → Access → Applications) per non avere il doppio login.
Al primo avvio l'app chiede di scegliere la password. Facoltativo: `SESSION_SECRET` (secret) per la firma delle sessioni.

## 3. Google Calendar (facoltativo)
1. Google Cloud → nuovo progetto → abilita Google Calendar API.
2. IAM → Service Accounts → crea → Keys → JSON.
3. Condividi il calendario weddingfotopier@gmail.com con l'email del service account (modifica eventi).
4. `npx wrangler secret put GOOGLE_SA_JSON` e incolla tutto il JSON.

Il PDF del contratto non si allega all'evento in automatico.
