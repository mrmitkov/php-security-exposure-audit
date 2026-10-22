# PHP Security Exposure Audit

Playbook Ansible in sola lettura per censire host Linux e valutare la mitigazione indicata nell'advisory per **CVE-2026-109618** e **CVE-2026-109619**. Produce report JSON per host e report consolidati CSV, HTML e PDF.

## Compatibilità

- Ansible Core >= 2.14 sul nodo di controllo.
- Nodo di controllo Linux, macOS o WSL; Ansible non supporta Windows come controller nativo.
- Target SLES 12/15, RHEL 7/8/9, Rocky Linux, AlmaLinux, Oracle Linux, Debian 11/12 e Ubuntu 20.04/22.04/24.04. I target devono esporre una shell POSIX, `find` GNU e `rpm` o `dpkg-query` per la discovery dei pacchetti.
- `wkhtmltopdf` sul nodo di controllo per generare il PDF (obbligatorio per impostazione predefinita).

Il playbook non installa, modifica o riavvia software sui target. Usa privilege escalation per leggere dati e percorrere i percorsi richiesti; i task di raccolta sono marcati `changed_when: false`. Per lo stato dei servizi usa `ansible.builtin.service_facts`, compatibile con systemd, SysV, Upstart e OpenRC, invece di interrogare direttamente `systemctl`; il rilevamento dei processi resta come fallback per istanze non gestite dal service manager. La creazione dei report avviene solo sul nodo di controllo.

Nei metadati Galaxy, `platforms` elenca le release OS supportate, indipendentemente dal fatto che siano eseguite su bare metal, VM o container. I runtime container sono indicizzati separatamente con i tag `docker`, `podman`, `lxc`, `lxd`, `kubernetes` e `containers`; non rappresentano ulteriori versioni di distribuzione.

## Struttura

```text
ansible.cfg
defaults/main.yml
inventory/hosts.ini
meta/main.yml
site.yml
tasks/
  main.yml
  php_audit.yml
  report.yml
templates/
  report.csv.j2
  report.html.j2
reports/                 # generata a runtime, esclusa da Git
```

## Configurazione ed esecuzione

1. Installa Ansible Core >= 2.14 sul controller e `wkhtmltopdf` se vuoi il report PDF.
2. Inserisci nella sezione `[php_audit]` di `inventory/hosts.ini` solo host per i quali hai autorizzazione.
3. Verifica la connettività SSH e i privilegi di lettura. Esempio su un host di test:

```sh
ansible-playbook -i "192.0.2.10," site.yml -u ansible --ask-pass --become --ask-become-pass
```

Per usare l'inventory del progetto, dopo aver aggiunto gli host:

```sh
ansible-playbook -i inventory/hosts.ini site.yml --ask-become-pass
```

L'esempio `192.0.2.10` è riservato alla documentazione: sostituiscilo con un host di test autorizzato. Non inserire password in chiaro nei file di inventory.

Per disabilitare facoltativamente il PDF, se `wkhtmltopdf` non è disponibile:

```sh
ansible-playbook -i inventory/hosts.ini site.yml -e audit_generate_pdf=false --ask-become-pass
```

I percorsi di scansione e la destinazione dei report sono configurabili in `defaults/main.yml` o con variabili extra, ad esempio `-e audit_output_dir=/percorso/report`.

## Report generati

Per ogni host raggiunto viene scritto `reports/<inventory-host>.json`. I report consolidati sono:

- `reports/php_security_audit.csv`
- `reports/php_security_audit.html`
- `reports/php_security_audit.pdf`

Se un host dell'inventory corrente non produce un risultato e il relativo JSON esiste già, il report consolidato riutilizza quel risultato precedente (abilitato per impostazione predefinita). Il report HTML e il CSV marcano chiaramente l'origine e la data del dato; l'HTML mostra inoltre un avviso con gli host ripresi da una scansione precedente. Questi risultati possono essere obsoleti e vanno verificati prima di considerarli rappresentativi dello stato corrente. Per disabilitare il recupero:

```sh
ansible-playbook -i inventory/hosts.ini site.yml -e audit_use_previous_results=false
```

Il CSV include anche i percorsi che contengono file PHP, i deployment WAR e i document root individuati. L'HTML contiene tabelle ordinabili, riepilogo e legenda dei risultati. La sezione container include le sonde Docker, Podman, LXC/LXD e Kubernetes quando i runtime e i permessi sono disponibili.

## Interpretazione della vulnerabilità

L'advisory allegato riporta CVE-2026-109618 e CVE-2026-109619 e indica che le versioni PHP dalla 5 in avanti potrebbero essere interessate. Le versioni dichiarate corrette sono **PHP 8.2.35, 8.3.36, 8.4.27 e 8.5.12**. Il report considera corretta anche una release patch successiva all'interno della stessa serie (8.2, 8.3, 8.4 o 8.5). Per queste versioni la classificazione è **FIXED VERSION**, indipendentemente dal valore di `session.upload_progress.enabled`. La versione rilevata è quella CLI, salvo fallback ai binari CGI/FPM quando la CLI non è presente; il SAPI web può differire. La valutazione non sostituisce la verifica degli advisory del vendor: le distribuzioni possono applicare backport senza cambiare la versione upstream mostrata da PHP.

- **NOT AFFECTED**: nessun eseguibile/pacchetto PHP rilevato e discovery pacchetti completata.
- **NEEDS REVIEW**: PHP rilevato ma il parametro non è determinabile, oppure l'inventario dei pacchetti è incompleto.
- **MITIGATED**: PHP rilevato e il parametro CLI risulta `Off`.
- **FIXED VERSION**: PHP rilevato a una versione corretta o patch successiva della stessa serie.
- **POTENTIALLY VULNERABLE**: PHP rilevato e il parametro CLI risulta `On`.

`php -r` legge il SAPI CLI; FPM, CGI e mod_php possono caricare file `php.ini` o configurazioni per-pool differenti. Un risultato `MITIGATED` deve essere verificato sul SAPI che serve l'applicazione. La disattivazione è una mitigazione temporanea riportata dall'advisory, non sostituisce l'aggiornamento a una versione corretta. Per versioni installate tramite una distribuzione, verificare gli advisory del vendor: un backport di sicurezza può non essere riconoscibile dal numero di versione upstream.

Un host con solo Tomcat/Java e senza PHP non è interessato da queste vulnerabilità specifiche di PHP. Tomcat, porte web e file WAR sono inventariati per contesto, ma non costituiscono da soli indicatori di esposizione PHP.

### Verifica manuale

Sul target, verificare la configurazione e la versione di ciascun SAPI PHP effettivamente usato:

```sh
php -v
php --ini
php -r 'var_export(ini_get("session.upload_progress.enabled"));'
php-fpm -i | grep session.upload_progress.enabled
find /usr /home /var/www /srv /opt -type f -name '*.php' 2>/dev/null
```

Controllare inoltre i file `php.ini`, le directory `conf.d`, la configurazione del pool FPM e i virtual host del server web. Dopo aver installato un aggiornamento del vendor, verificare nuovamente la versione dal package manager e consultare l'advisory ufficiale PHP e quella del sistema operativo per la corrispondenza della CVE.

## Contenitori: Docker, Podman, LXC/LXD e Kubernetes

Per impostazione predefinita il playbook tenta la lettura dei container in esecuzione gestiti da Docker e Podman rootful, dei container LXC classic attivi (`lxc-ls`/`lxc-attach`), delle istanze LXD in stato `RUNNING` (`lxc list`/`lxc exec`) e dei container nei pod Kubernetes in stato `Running`. Le sonde avviano soltanto processi temporanei `sh`, `php -v` e `php -r` nei container; non modificano immagini o filesystem. Docker, Podman rootful e LXC classic/LXD devono essere accessibili all'utente remoto con privilege escalation; `kubectl` viene eseguito come utente SSH e deve avere un contesto autorizzato con permessi di lettura dei pod e `pods/exec`. La scansione Podman usa il contesto rootful e non include i container rootless dei singoli utenti. Gli errori di accesso o l'assenza di una shell sono riportati come risultati da verificare, non come “non vulnerabile”. È possibile disabilitare una sonda con `-e audit_scan_docker_containers=false`, `-e audit_scan_podman_containers=false`, `-e audit_scan_lxc_containers=false` o `-e audit_scan_kubernetes_pods=false`.

Le scansioni dei container sono limitate alle istanze in esecuzione e il valore PHP è quello del SAPI CLI nel container; non sostituisce una verifica del SAPI web. Per cluster o ambienti con molti container, considerare tempi e autorizzazioni prima di abilitare le sonde.
