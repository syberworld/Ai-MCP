# MEGA MCP Server

Server MCP che consente ai modelli di operare su un account [MEGA](https://mega.io) tramite le API di MEGA
(client crittografato end-to-end basato su [`megajs`](https://mega.js.org/)). Tutta la cifratura/decifratura
avviene in locale: le credenziali e le chiavi non lasciano la macchina che esegue il server.

## Installazione

```bash
cd Storage/Mega
npm install
npm run build
```

Richiede Node.js 18 o superiore.

## Configurazione

Variabili d'ambiente:

| Variabile | Obbligatoria | Descrizione |
|-----------|--------------|-------------|
| `MEGA_EMAIL` | sì* | Email dell'account MEGA |
| `MEGA_PASSWORD` | sì* | Password dell'account |
| `MEGA_2FA_CODE` | no | Codice 2FA (se attivo). Poiché scade, è preferibile passarlo al tool `mega_login` |
| `MEGA_LOCAL_ROOT` | no | Se impostata, upload/download locali sono confinati in questa cartella |

\* Non servono per i tool sui link pubblici (`mega_public_*`) o se si usa `mega_login` con credenziali esplicite.

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "mega": {
      "command": "node",
      "args": ["/percorso/assoluto/Ai-MCP/Storage/Mega/dist/index.js"],
      "env": {
        "MEGA_EMAIL": "you@example.com",
        "MEGA_PASSWORD": "your-password"
      }
    }
  }
}
```

Con Claude Code:

```bash
claude mcp add mega -e MEGA_EMAIL=you@example.com -e MEGA_PASSWORD=your-password -- node /percorso/assoluto/Ai-MCP/Storage/Mega/dist/index.js
```

## Percorsi remoti

| Forma | Significato |
|-------|-------------|
| `/` , `/Documenti/file.txt` | Cloud Drive (radice e percorsi) |
| `trash:/...` | Cestino (Rubbish Bin) |
| `inbox:/...` | Inbox |
| `shares:/<NomeCondivisione>/...` | Cartelle condivise da altri utenti |
| `id:<handle>` | Nodo indicato tramite il suo handle MEGA (8 caratteri) |

## Tool disponibili

**Account e sessione**
- `mega_login` – login / cambio account / codice 2FA (il login è altrimenti automatico)
- `mega_logout` – chiude la sessione
- `mega_account_info` – tipo account, spazio usato/totale, quota di trasferimento
- `mega_reload` – ricarica l'albero dei file dal server

**Navigazione**
- `mega_list` – contenuto di una cartella (anche ricorsivo)
- `mega_get_info` – metadati di file/cartella
- `mega_search` – ricerca per nome (sottostringa o regex, filtro file/cartelle)
- `mega_list_shares` – condivisioni in ingresso e nodi esportati con link pubblico

**Modifica**
- `mega_mkdir` – crea cartelle (anche intermedie)
- `mega_rename` – rinomina
- `mega_move` – sposta (anche per ripristinare dal cestino)
- `mega_copy` – copia lato server
- `mega_delete` – sposta nel cestino o elimina definitivamente
- `mega_empty_trash` – svuota il cestino
- `mega_set_label` – etichetta colore
- `mega_set_favorite` – preferiti

**Trasferimenti**
- `mega_upload` – carica file o intere cartelle locali
- `mega_write_file` – crea un file da contenuto testo/base64
- `mega_download` – scarica file o cartelle in locale
- `mega_read_file` – legge il contenuto (o un intervallo di byte) di un file

**Condivisione**
- `mega_create_link` – crea link pubblico (con o senza chiave nell'URL)
- `mega_remove_link` – rimuove il link pubblico
- `mega_set_thumbnail` – imposta miniatura/anteprima di un file

**Link pubblici** (non richiedono login)
- `mega_public_info` – metadati e contenuto di un link file/cartella
- `mega_public_read` – legge un file da link pubblico
- `mega_public_download` – scarica un link pubblico in locale
- `mega_import_link` – importa nel proprio account un link pubblico (file o cartella)

**Avanzato**
- `mega_api_request` – invia un comando raw alle API MEGA (`{"a": "..."}`) con la sessione corrente, per operazioni non coperte dagli altri tool

## Note

- MEGA non supporta la modifica in-place: `mega_write_file` con `overwrite=true` carica la nuova versione e sposta la vecchia nel cestino.
- I tool distruttivi (`mega_delete`, `mega_empty_trash`, `mega_api_request`) sono marcati con `destructiveHint`.
- La condivisione di cartelle con specifici contatti MEGA non è supportata dalla libreria `megajs`; è raggiungibile solo tramite `mega_api_request`.
