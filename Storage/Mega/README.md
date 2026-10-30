# MEGA MCP Server (PHP)

Server [MCP](https://modelcontextprotocol.io) in PHP che consente ai modelli di operare su un account
[MEGA](https://mega.io) tramite le API di MEGA. È pensato per essere ospitato su un server web PHP e
raggiunto via HTTP (trasporto *Streamable HTTP*); l'accesso è ristretto tramite token segreti.

La crittografia del client MEGA (login, chiavi, attributi, upload/download cifrati AES-CTR con MAC) è
implementata in [`src/Mega`](src/Mega): file e chiavi vengono cifrati/decifrati sul server che ospita l'MCP,
MEGA riceve solo dati cifrati.

## Requisiti

- PHP 8.1+ con estensioni `curl`, `openssl`, `mbstring`, `json`
- [Composer](https://getcomposer.org) (dipendenza: `phpseclib/phpseclib` per l'RSA del login)
- Un server web (Apache, Nginx + PHP-FPM, …) con HTTPS

## Installazione

```bash
cd Storage/Mega
composer install --no-dev
cp config/config.example.php config/config.php
php bin/generate-token.php   # token di accesso MCP
php bin/generate-token.php   # session_secret
```

Compila `config/config.php`:

```php
'auth_tokens' => ['<token generato>'],
'mega' => [
    'email' => 'tu@example.com',
    'password' => '...',
    'storage_dir' => __DIR__ . '/../var',   // scrivibile, NON accessibile dal web
    'session_secret' => '<secondo token>',
],
```

In alternativa si possono usare variabili d'ambiente (hanno la precedenza sul file):
`MCP_AUTH_TOKENS` (separati da virgola), `MEGA_EMAIL`, `MEGA_PASSWORD`, `MEGA_SESSION_SECRET`, `MEGA_STORAGE_DIR`.

### Web server

Il document root deve puntare a **`public/`**: l'endpoint MCP è `public/index.php`.

- **Apache**: `public/.htaccess` inoltra l'header `Authorization` a PHP. Se non puoi cambiare il
  document root, il `.htaccess` nella cartella `Storage/Mega` blocca l'accesso a tutto tranne `public/`
  (endpoint: `https://tuo-dominio/.../Storage/Mega/public/`).
- **Nginx**:

  ```nginx
  location /mega-mcp/ {
      alias /percorso/Ai-MCP/Storage/Mega/public/;
      fastcgi_pass unix:/run/php/php8.3-fpm.sock;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME /percorso/Ai-MCP/Storage/Mega/public/index.php;
      fastcgi_param HTTP_AUTHORIZATION $http_authorization;
  }
  ```

Usa sempre HTTPS: il token viaggia in ogni richiesta.

## Accesso ristretto

- Ogni richiesta deve avere l'header `Authorization: Bearer <token>`; senza token valido la risposta è `401`.
  I token sono confrontati in tempo costante e devono essere lunghi almeno 32 caratteri.
- Se non è configurato alcun token il server non si avvia (risponde `500`) invece di restare aperto.
- Si possono configurare più token (uno per client) e revocarne uno togliendolo dalla lista.
- `allow_query_token` (disattivato di default) permette `?token=...` nell'URL per i client che non
  possono inviare header: è meno sicuro perché gli URL finiscono nei log.
- `allowed_origins` limita le richieste provenienti da browser a specifiche origini.
- Le credenziali MEGA restano sul server; la sessione MEGA viene salvata in `storage_dir` cifrata
  con AES-256-GCM (chiave derivata da `session_secret`), così il login non si ripete a ogni richiesta.
- `mega_upload_from_url` rifiuta indirizzi privati/riservati (anche dopo redirect) per evitare SSRF.

## Collegare un client

Claude Code:

```bash
claude mcp add --transport http mega https://tuo-dominio/mega-mcp/ --header "Authorization: Bearer <token>"
```

Configurazione JSON generica (client che supportano server HTTP remoti con header):

```json
{
  "mcpServers": {
    "mega": {
      "type": "http",
      "url": "https://tuo-dominio/mega-mcp/",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

### Account con autenticazione a due fattori

Il server non può generare il codice 2FA. Al primo utilizzo chiedi al modello di eseguire
`mega_login` con `twoFactorCode` (il codice attuale dell'app di autenticazione): la sessione viene
salvata e riutilizzata finché resta valida su MEGA.

## Percorsi remoti

| Forma | Significato |
|-------|-------------|
| `/` , `/Documenti/file.txt` | Cloud Drive |
| `trash:/...` | Cestino (Rubbish Bin) |
| `inbox:/...` | Inbox |
| `shares:/<NomeCondivisione>/...` | Cartelle condivise da altri utenti |
| `id:<handle>` | Nodo indicato tramite il suo handle MEGA |

MEGA permette nomi duplicati nella stessa cartella: in quel caso il percorso indica il primo; usa `id:<handle>` per essere precisi.

## Tool

| Gruppo | Tool |
|--------|------|
| Account | `mega_login`, `mega_logout`, `mega_account_info`, `mega_reload` |
| Navigazione | `mega_list`, `mega_get_info`, `mega_search`, `mega_list_shares` |
| Modifica | `mega_mkdir`, `mega_rename`, `mega_move`, `mega_copy`, `mega_delete`, `mega_restore`, `mega_empty_trash`, `mega_set_label`, `mega_set_favorite` |
| Contenuti | `mega_read_file`, `mega_write_file`, `mega_upload_from_url` |
| Condivisione | `mega_create_link`, `mega_remove_link` |
| Link pubblici | `mega_public_info`, `mega_public_read`, `mega_import_link` |
| Avanzato | `mega_api_request` (comando raw alle API MEGA con la sessione corrente) |

Note:
- `mega_delete` sposta nel cestino ricordando la cartella d'origine, così `mega_restore` può riportarlo lì.
- `mega_write_file` con `overwrite=true` carica la nuova versione e sposta la vecchia nel cestino.
- I limiti di lettura/upload sono in `limits` nel file di configurazione.
- La condivisione di cartelle con specifici contatti MEGA non ha un tool dedicato: si può fare con `mega_api_request`.

## Test

```bash
php tests/run.php
```

La suite verifica la crittografia con vettori generati dalla libreria `megajs` e prova l'endpoint MCP
end-to-end (autenticazione, tutti i principali tool) contro un finto server API MEGA locale
(`tests/mock/router.php`). Non serve un account MEGA, ma di conseguenza non sostituisce una prova sul servizio reale.
