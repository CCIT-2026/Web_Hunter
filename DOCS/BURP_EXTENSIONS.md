# Estensioni Essenziali per Burp Suite

Burp Suite è il proxy HTTP primario per l'analisi e lo sfruttamento delle vulnerabilità web. La versione Community ha alcune limitazioni che possono essere superate (e le sue funzionalità ampliate enormemente) grazie alle estensioni installabili tramite il **BApp Store**.

Di seguito le estensioni fondamentali menzionate nell'ARSENALE, con una spiegazione dettagliata, istruzioni per l'installazione e casi d'uso pratici.

## 🛠️ Come installare le estensioni

L'installazione delle estensioni in Burp Suite avviene tramite la scheda **Extensions** (o **Extender** nelle versioni più vecchie):

1. Vai sulla scheda **Extensions** -> **BApp Store**.
2. Cerca il nome dell'estensione desiderata.
3. Clicca su **Install**.

### ⚠️ Requisiti Runtime (FONDAMENTALE per l'uso Offline)
Molte estensioni non sono scritte in Java ma in Python o Ruby. Affinché funzionino, Burp ha bisogno dei relativi interpreti:
* **Jython (per estensioni Python, es. Autorize):**
  1. Scarica il file `jython-standalone-X.X.X.jar` dal sito ufficiale di Jython.
  2. In Burp, vai in **Extensions** -> **Extensions settings** -> **Python Environment**.
  3. Seleziona il percorso in cui hai salvato il file `.jar`.
* **JRuby (per estensioni Ruby):**
  1. Scarica il file `jruby-complete-X.X.X.jar` dal sito ufficiale.
  2. In Burp, vai in **Extensions** -> **Extensions settings** -> **Ruby Environment**.
  3. Seleziona il percorso del file `.jar`.

**Importante in ottica A/D e Offline:** Devi scaricare i `.jar` e installare tutte le estensioni dal BApp Store **prima della gara, avendo connessione a Internet**, altrimenti le estensioni non partiranno in ambiente isolato.

---

## 1. JWT Editor & SignSaboteur

### A cosa servono:
Queste estensioni sono essenziali per lavorare con i JSON Web Token (JWT).
* **JWT Editor** decodifica automaticamente i token JWT permettendoti di leggerne l'header e il payload e di modificarne i valori direttamente nella finestra del proxy o nel Repeater. Permette anche di generare chiavi RSA o manipolare le firme.
* **SignSaboteur** è specifico per l'attacco automatico o guidato contro i token firmati, semplificando la compromissione di sessioni se il server usa implementazioni deboli.

### Come si usano:
Una volta installate, aggiungono tab specifiche alla vista della singola richiesta/risposta in Burp.
Se trovi un JWT in un header `Authorization: Bearer <token>` o in un cookie, l'estensione lo evidenzia. Modificando i campi nel payload (es. da `{"role": "user"}` a `{"role": "admin"}`), puoi usare l'estensione per ricalcolare la firma o forzarla a zero (algoritmo "none").

### 🎯 Caso d'Uso Pratico: Privilege Escalation via "alg: none"
In gara catturi una richiesta in Burp verso `/api/profile` con il tuo JWT di utente base.
1. Manda la richiesta al **Repeater** (`Ctrl+R`).
2. Vai nel tab aggiunto da **JWT Editor**.
3. Nel campo payload, cambi la dicitura `"username": "mimmo"` in `"username": "admin"`.
4. Nel pannello inferiore, clicchi su "Attack" -> "None Signing Algorithm". L'estensione modificherà l'header del JWT settando `alg: none` e rimuoverà la firma.
5. Invii la richiesta. Se il backend è vulnerabile, ti accetterà come admin restituendoti la flag e potrai copiare il payload per il tuo exploit definitivo.

---

## 2. Autorize (o Auth Analyzer)

### A cosa servono:
Servono a trovare automaticamente vulnerabilità di tipo **IDOR** (Insecure Direct Object Reference) e rotture nei controlli degli accessi (Broken Access Control).

### Come si usano:
Autorize lavora in background. Gli fornisci il cookie o l'header di autorizzazione di un utente con privilegi bassi. Mentre tu navighi l'applicazione come utente "Admin", Autorize clona segretamente ogni tua richiesta e la ripete aggiungendoci il cookie dell'utente a basso privilegio. Poi, ti colora in verde o in rosso i risultati per mostrarti se l'utente povero ha avuto accesso alle pagine dell'admin.

### 🎯 Caso d'Uso Pratico: Trovare l'endpoint senza permessi
1. Ti logghi nel servizio come utente `attacker` e copi il tuo `Cookie: session=xyz`.
2. Vai nel tab di **Autorize** e incolli il cookie dell'utente `attacker`. Attivi Autorize ("Autorize is on").
3. Apri un altro browser (o un'altra sessione), ti logghi sul TUO vulnbox come utente amministratore legit.
4. Inizi a navigare come admin: apri `/api/users/all`, `/api/settings/flag`.
5. Torni in Burp, tab Autorize: vedi una riga verde su `/api/users/all`. Significa che l'utente `attacker` è riuscito a leggere la lista utenti riservata perché lo sviluppatore si è scordato il controllo dei permessi su quell'API. Ora sai dove colpire!

---

## 3. Turbo Intruder

### A cosa servono:
Turbo Intruder è progettato per inviare un numero massivo di richieste HTTP a una velocità estrema. È programmato tramite script in Python e bypassa i colli di bottiglia tipici di Burp, sfuggendo ai limiti della versione Community.

### Come si usano:
Selezioni una richiesta, fai tasto destro e scegli **Extensions -> Turbo Intruder -> Send to Turbo Intruder**. Si apre una finestra con il testo della richiesta in alto e uno script Python in basso che definisce come le richieste verranno sparate (multi-threading, delay, ecc.).

### 🎯 Caso d'Uso Pratico: Race Condition (Single-Packet Attack)
Hai trovato un endpoint `/vote` che accetta il voto per il tuo team. Il server verifica se hai già votato prima di registrare il voto, ma forse c'è una finestra di tempo impercettibile tra il controllo e la scrittura nel DB (Race condition).
1. Mandi la richiesta `/vote` a Turbo Intruder.
2. Usi uno script predefinito (es. `race-single-packet.py`) che sfrutta l'HTTP/2 per inviare 20 richieste contemporanee racchiuse in un singolo frame di rete.
3. Premi "Attack".
4. Vedi 20 risposte. Se più di una risponde con `200 OK` (e il tuo punteggio sale di +2 o +3 invece che di +1), hai appena sfruttato una race condition per moltiplicare i tuoi voti.

---

## 4. Param Miner

### A cosa servono:
A scoprire parametri GET, POST, o header HTTP "nascosti" che l'applicazione accetta ma che non sono documentati o linkati da nessuna parte. Trova gli "ingressi secondari" usati spesso per debugging, che possono nascondere vulnerabilità (es. `?debug=1`, `?admin_override=true`).

### Come si usano:
Tasto destro su una richiesta intercettata nel traffico -> **Extensions -> Param Miner -> Guess GET parameters** (oppure headers, ecc.). Inizierà a provare migliaia di nomi di parametri in background sfruttando dizionari propri.

### 🎯 Caso d'Uso Pratico: Web Cache Poisoning
Mentre analizzi la pagina principale `/home`, fai partire Param Miner per cercare header nascosti.
Dopo qualche minuto, nella tab **Extender** -> **Output** vedi che Param Miner ha scoperto che il server reagisce in modo anomalo se riceve l'header `X-Forwarded-Host`.
Se modifichi la tua richiesta in Repeater inserendo `X-Forwarded-Host: evil.com`, noti che tutti i link e gli script caricati nella pagina HTML iniziano a puntare al tuo dominio. Hai appena trovato un punto d'ingresso per un attacco di Web Cache Poisoning, che potrai usare per distribuire XSS agli avversari.

---

## 5. Hackvertor

### A cosa servono:
È una serie di "tag" simili all'HTML che puoi inserire direttamente nel testo delle tue richieste nel Repeater. Permette di codificare, decodificare, fare l'hash o criptare parti del testo *al volo* prima che la richiesta parta verso il server.

### Come si usano:
In Repeater, evidenzi una stringa, fai tasto destro -> **Extensions -> Hackvertor** e scegli il formato, ad esempio "Encode -> Base64". La stringa diventerà `<@base64>la_tua_stringa<@/base64>`. Quando clicchi "Send", Burp trasformerà il testo in Base64 prima di inviarlo.

### 🎯 Caso d'Uso Pratico: SQL Injection rapida in Base64
Un servizio accetta un parametro JSON codificato in base64: `data=eyB1c2VyOiAnYWRtaW4nIH0=`.
Normalmente, per testare una SQL Injection o aggiungere degli apici, dovresti prendere la stringa, decodificarla nel browser, inserire un `'`, ricodificarla in base64 e incollarla di nuovo in Burp. Scomodissimo e lento.
Con Hackvertor:
1. Sostituisci il valore criptato in Repeater con: `<@base64>{"user":"admin'"}<@/base64>`.
2. Tu continui a lavorare leggendo il JSON in chiaro nel tuo Repeater, potendo facilmente provare diverse query (`"admin' OR 1=1--"`).
3. Hackvertor penserà a codificare il tutto in Base64 automaticamente al momento di inviare la richiesta. Il tuo iter di prova degli exploit diventa velocissimo.

---

## 6. Logger++

### A cosa servono:
Burp ha già una cronologia HTTP (`HTTP history`), ma Logger++ va molto oltre: registra rigorosamente tutto il traffico (anche le richieste "invisibili" generate dalle altre estensioni, da Intruder o da scanner passivi in background) e offre filtri di ricerca potentissimi stile Wireshark.

### Come si usano:
L'estensione aggiunge un tab principale "Logger++" a Burp. Da lì puoi vedere log estremamente dettagliati e cercare dentro l'intero storico usando query specifiche.

### 🎯 Caso d'Uso Pratico: Ritrovare un errore sfuggito
Mentre avevi Autorize attivo e navigavi un po' a caso, ricordi di aver visto di sfuggita un errore 500 che rivelava parte di uno stack trace in SQL, ma hai perso l'esatta richiesta che lo ha generato.
1. Invece di rifare l'intero flusso navigando alla cieca, apri il tab di Logger++.
2. Metti il filtro: `Response.Status == 500 AND Response.Body MATCHES "SQL syntax"`.
3. Logger++ filtra immediatamente tra le migliaia di richieste in memoria, mostrandoti la singola chiamata incriminata e permettendoti di inviarla subito al Repeater per sfruttarla.
