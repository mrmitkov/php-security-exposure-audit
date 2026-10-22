# PHP Security Exposure Audit

## Panoramica

PHP Security Exposure Audit è un playbook Ansible in sola lettura che raccoglie informazioni dagli host Linux autorizzati e genera report sull'esposizione potenziale a CVE-2026-109618 e CVE-2026-109619. I risultati aiutano a individuare i sistemi da verificare: non sostituiscono l'analisi dell'advisory del vendor né una verifica della configurazione del servizio PHP effettivamente esposto.

Il playbook non installa, modifica o riavvia software sui sistemi controllati. I dati vengono raccolti sugli host e i report vengono creati sul nodo di controllo Ansible.

## Cosa controlla

Il playbook raccoglie informazioni su:

- pacchetti ed eseguibili PHP rilevati, relative versioni e configurazione CLI di `session.upload_progress.enabled`;
- file PHP e percorsi che li contengono;
- servizi e processi correlati;
- document root, deployment WAR e informazioni di contesto sui server web;
- container Docker e Podman rootful, LXC/LXD e pod Kubernetes in esecuzione, se le sonde sono abilitate e accessibili.

Le sonde nei container avviano solo comandi temporanei di lettura. Non modificano immagini o filesystem. Il rilevamento nei container è limitato alle istanze in esecuzione. La sonda Podman usa il contesto rootful e non rileva i container rootless dei singoli utenti.

## Requisiti

- Ansible Core 2.14 o superiore sul nodo di controllo.
- Nodo di controllo Linux, macOS o WSL. Ansible non supporta Windows come controller nativo.
- Host Linux compatibili (tra cui SLES, RHEL e derivate, Debian e Ubuntu) con shell POSIX, `find` GNU e `rpm` o `dpkg-query`.
- `wkhtmltopdf` sul controller per generare il PDF, abilitato per impostazione predefinita.
- Credenziali SSH e privilegi di lettura adeguati. Le sonde Kubernetes richiedono inoltre un contesto `kubectl` autorizzato con permessi di lettura dei pod e `pods/exec`.

## Utilizzo

1. Aggiungere all'inventory solo sistemi per i quali si dispone di autorizzazione.
2. Verificare prima la connettività SSH e i privilegi di lettura su un host di test.
3. Eseguire il playbook dalla directory del progetto:

```sh
ansible-playbook -i inventory/hosts.ini site.yml --ask-become-pass
```

Per una prova su un singolo host autorizzato:

```sh
ansible-playbook -i "192.0.2.10," site.yml -u ansible --ask-pass --become --ask-become-pass
```

`192.0.2.10` è un indirizzo riservato alla documentazione: sostituirlo con l'indirizzo di un host autorizzato. Non inserire password in chiaro nell'inventory.

Se `wkhtmltopdf` non è disponibile, è possibile disabilitare la generazione PDF:

```sh
ansible-playbook -i inventory/hosts.ini site.yml -e audit_generate_pdf=false --ask-become-pass
```

Le sonde container possono essere disabilitate singolarmente con `audit_scan_docker_containers`, `audit_scan_podman_containers`, `audit_scan_lxc_containers` e `audit_scan_kubernetes_pods`. Le directory di scansione e la destinazione dei report sono configurabili in `defaults/main.yml`.

## Report

Per ogni host raggiunto viene generato un report JSON. I risultati consolidati sono:

- `reports/php_security_audit.csv`
- `reports/php_security_audit.html`
- `reports/php_security_audit.pdf` (se la generazione PDF è abilitata)

Il CSV include anche i percorsi contenenti file PHP, i deployment WAR e i document root rilevati. I report possono contenere nomi host, percorsi e dettagli dell'infrastruttura: conservarli e condividerli secondo le policy di sicurezza della propria organizzazione.

Se un host dell'inventory corrente non ha prodotto dati nella scansione e il suo JSON di una scansione precedente è presente nella directory dei report, i report consolidati riutilizzano quei dati per impostazione predefinita. HTML e CSV indicano la fonte e la data; l'HTML evidenzia gli host con dati precedenti. Questi risultati potrebbero essere obsoleti e non vanno considerati una fotografia aggiornata. Per disattivare il recupero, eseguire il playbook con `-e audit_use_previous_results=false`.

## Interpretazione dei risultati

- **NOT AFFECTED**: non sono stati rilevati eseguibili o pacchetti PHP e la discovery dei pacchetti è stata completata.
- **NEEDS REVIEW**: PHP è stato rilevato ma il parametro non è determinabile, oppure l'inventario dei pacchetti è incompleto.
- **MITIGATED**: PHP è stato rilevato e il valore CLI del parametro risulta `Off`.
- **FIXED VERSION**: PHP è rilevato a una versione corretta o patch successiva della stessa serie.
- **POTENTIALLY VULNERABLE**: PHP è stato rilevato e il valore CLI del parametro risulta `On`.

Le versioni PHP dichiarate corrette sono **8.2.35, 8.3.36, 8.4.27 e 8.5.12**. Il report considera corrette anche le release patch successive nella stessa serie (rispettivamente 8.2, 8.3, 8.4 e 8.5) e assegna loro **FIXED VERSION**, indipendentemente dal valore CLI di `session.upload_progress.enabled`. La versione rilevata è quella CLI, salvo fallback ai binari CGI/FPM quando la CLI non è presente; il SAPI web può differire. La classificazione resta una valutazione di esposizione, non una verifica definitiva delle CVE.

Il valore letto con `php -r` riguarda il SAPI CLI. PHP-FPM, CGI e mod_php possono usare file `php.ini` o configurazioni per-pool differenti: verificare il SAPI che serve effettivamente l'applicazione. Anche uno stato **MITIGATED** richiede questa verifica. La disattivazione del parametro è una mitigazione temporanea indicata dall'advisory e non sostituisce l'aggiornamento a una versione corretta. Le distribuzioni possono applicare backport senza cambiare la versione upstream: verificare gli advisory del vendor.

Un host che esegue solo Tomcat/Java e non ha PHP non è interessato da queste specifiche vulnerabilità PHP. Tomcat, le porte web e i file WAR sono raccolti per fornire contesto e non rappresentano, da soli, indicatori di esposizione PHP.

## Verifica manuale

Sul sistema interessato, controllare la versione e la configurazione di ciascun SAPI PHP effettivamente usato:

```sh
php -v
php --ini
php -r 'var_export(ini_get("session.upload_progress.enabled"));'
php-fpm -i | grep session.upload_progress.enabled
```

Esaminare anche i file `php.ini`, le directory `conf.d`, la configurazione dei pool FPM e i virtual host del server web. Dopo un aggiornamento, verificare la versione installata tramite il package manager e consultare gli advisory ufficiali PHP e del sistema operativo per la corrispondenza delle CVE.
