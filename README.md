# pve-patcher

Aplicação web (LXC no Proxmox) que descobre as VMs QEMU dos clusters, entra por SSH, lista as atualizações
pendentes, cruza com CVEs (com criticidade, KEV e EPSS) e atualiza sob comando, uma VM por vez.

Distros suportadas nas VMs: Debian, Ubuntu, AlmaLinux/Rocky e Alpine. Só VMs QEMU (sem containers LXC).

## Arquitetura

```
 Navegador ──HTTPS──> [proxy opcional] ──HTTPS──> LXC pve-patcher :8443 (autoassinado; :8080 redireciona)
                                                  ├─ PvePatcher.Web  (Blazor Server, SQLite, fila, agendador)
                                                  ├─ OpenBao 127.0.0.1:8200 (token PVE, chave SSH, chave NVD)
                                                  └─> API do PVE (token de serviço)  /  SSH nas VMs (chave do cofre)
```

| Projeto | Função |
|---|---|
| `PvePatcher.Core` | Contratos (interfaces e records) |
| `PvePatcher.Integrations` | OpenBao, cliente da API do PVE, login via PVE, escolha de IP |
| `PvePatcher.Targets` | SSH sem agente, scan e upgrade nas VMs (`patcher-agent` embutido, enviado pelo stdin) |
| `PvePatcher.Vuln` | Feeds OSV/KEV/EPSS/NVD e o cruzamento pacote x CVE |
| `PvePatcher.Web` | Persistência, fila, agendador, autenticação e UI (este README) |

### Serviços do Web

- **Estado atual apenas**: SQLite em `Data:Path` (`/var/lib/pve-patcher/state.db`, WAL). Cada scan sobrescreve o
  anterior; do upgrade guarda-se só o log da última execução por VM. Sem histórico. Esquema por migrations do EF Core
  (aplicadas na inicialização). A lista completa de pacotes instalados não é persistida, só pendentes e findings.
- **Segredos nunca no SQLite**: token do PVE por cluster, chave SSH e chave do NVD ficam no OpenBao (`ISecretStore`).
  A UI escreve/rotaciona, mas nunca mostra o valor (só "definido em ..." e a chave pública).
- **Fila única** (`JobQueue` + `JobRunner`): scans, upgrades e atualização de feeds executam um de cada vez.
  Log ao vivo por job; ao terminar vira o "último log" da VM.
- **Discovery**: a cada 15 min (configurável) e no botão "Descobrir agora". VMs novas entram; as que sumiram do
  cluster são removidas com seus dados; falha em um cluster não afeta os outros. Se o guest agent não responde, NICs e
  SO anteriores são mantidos (o SSH não depende do agent).
- **Agendador**: cron de 5 campos (padrão `0 3 * * *`, `America/Sao_Paulo`). O ciclo enfileira primeiro a atualização
  dos feeds (com as releases em uso) e depois um scan por VM ligada.
- **Scan de uma VM**: monta o alvo SSH, conecta, escaneia, cruza com o `IVulnerabilityMatcher`, enriquece no NVD os CVEs
  achados e cruza de novo. Primeira conexão grava a host key (TOFU). Host key diferente bloqueia scan/upgrade até um
  usuário com `VM.PowerMgmt` aceitar a nova chave na tela da VM.
- **Upgrade** (só sob comando): snapshot opcional `patcher-yyyyMMdd-HHmm` (depois apaga os `patcher-*` antigos; se o
  snapshot falhar, aborta sem tocar na VM), `IHostUpdater`, reboot opcional (só se marcado **e** exigido; espera o guest
  agent por 5 min e o SSH por até 3 min) e re-scan. "Só segurança" atualiza apenas os binários com finding
  `FixedByPendingUpdate`; se não houver nenhum, não roda.
- **Cofre selado**: banner vermelho global; o app não cai. O login não depende do cofre (usa a senha do usuário no PVE);
  discovery, scans e upgrades falham com "Cofre selado — rode unseal no LXC".

## Instalação passo a passo

1. **Criar o LXC** (no nó PVE):
   `./create-lxc.sh --vmid 150 --hostname pve-patcher --bridge vmbr0 --vlan 20 --ip 172.22.20.50/24 --gw 172.22.20.1 --storage local-lvm`
   (`deploy/lxc/create-lxc.sh`; baixa o template Debian 13 com `pveam` se faltar; 1 vCPU, 1 GB, 8 GB, onboot).
2. **Publicar** (no Windows): `.\publish.ps1` gera `publish/pve-patcher.tar.gz` (self-contained linux-x64 + `deploy/`).
   Copie para o LXC e extraia: `tar xzf pve-patcher.tar.gz`.
3. **Instalar** (no LXC, root): `sh deploy/lxc/install.sh`. Ele cria o usuário `pve-patcher`, `/opt/pve-patcher`,
   `/etc/pve-patcher`, `/var/lib/pve-patcher`, a unit `pve-patcher.service` e, nesta ordem, chama
   `deploy/openbao/install-openbao.sh` e `deploy/openbao/init-openbao.sh` (guarde as chaves de unseal impressas).
   Use `--skip-openbao` se o cofre já existe.
4. **Configurar o cluster** em `/etc/pve-patcher/appsettings.Production.json` (veja abaixo) e `systemctl restart pve-patcher`.
5. **Preparar cada cluster PVE**: rode `deploy/proxmox/pve-role.sh` em um nó (cria role, usuário e token; imprime o token).
6. **Gravar o token no cofre**: faça login na UI (o login não precisa do cofre, mas o cofre precisa estar liberado
   para gravar), abra *Configurações > Clusters > Editar* e informe `token_id` e `token_secret`. Alternativa por linha
   de comando: `BAO_TOKEN=... deploy/lxc/set-cluster-token.sh prod 'pve-patcher@pve!svc'`.
7. **Chave SSH**: em *Configurações > Chave SSH padrão*, gere um par ed25519 (a privada vai direto ao cofre) ou cole uma
   existente. A tela mostra a chave pública e o comando de bootstrap.
8. **Preparar as VMs** (como root em cada VM):
   `curl -fsSLk --pinnedpubkey 'sha256//<pin>' https://<este-host>:8443/bootstrap-vm.sh | sh -s -- --pubkey '<chave pública>' --user patcher`
   (copie o comando pronto da tela: o `-k` aceita o certificado autoassinado e o `--pinnedpubkey` exige a chave do app)
   (opcional `--from 172.22.20.50` restringe a chave ao IP do LXC). O script (`deploy/target/bootstrap-vm.sh`,
   servido por um endpoint anônimo, sem segredos) é idempotente e:
   - cria o usuário `patcher` (sem senha, login só pela chave, `no-pty`/sem forwarding no `authorized_keys`);
   - instala `/usr/local/sbin/patcher-upgrade` (root, 0755): upgrade seletivo que só aceita nomes de pacote simples
     (sem opções, caminhos, versões, curingas nem `.deb/.rpm/.apk` locais);
   - grava `/etc/sudoers.d/patcher` (validado com `visudo`) liberando **só** estes comandos, com argumentos fixos:

     | Família | Comandos liberados |
     |---|---|
     | apt | `apt-get -q -o Dpkg::Use-Pty=0 update`, `apt-get -y -q -o Dpkg::Use-Pty=0 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade` |
     | dnf | `dnf -q makecache`, `dnf -y upgrade` |
     | apk | `apk update`, `apk upgrade --no-progress` |
     | todas | `systemctl reboot` (ou `reboot` sem systemd), `/usr/local/sbin/patcher-upgrade <pacotes>` |

   A cada execução o app abre a conexão SSH e envia o `patcher-agent` pelo stdin (`sh -s -- <subcomando>`, com o
   próprio usuário). Listar pacotes e checar reboot não usam sudo; só os passos acima usam `sudo -n`. Depois de
   atualizar o app, rode o bootstrap de novo se o `patcher-agent` mudar esses comandos. Root ou uma conta com
   **sudo NOPASSWD** total (sem `requiretty`) também funcionam, sem bootstrap. Um usuário/chave diferente por VM pode
   ser definido no cofre em `ssh/vm/{cluster}/{vmid}`.
   **Endereço do comando**: em *Configurações > Chave SSH padrão > Comando de bootstrap* defina a URL que as VMs usam
   (ex.: `https://patcher.minetto.dev.br`) e como o `curl` confere o certificado:
   - *Pinar a chave do app*: acesso direto à 8443 com o certificado autoassinado;
   - *Validar a cadeia*: proxy com certificado que as VMs confiam. Se for de CA interna, a CA precisa estar instalada nas VMs.

   Vazio = `Bootstrap:PublicBaseUrl` / `Bootstrap:PinAppCertificate` do appsettings, ou o endereço da própria página.
9. **Abrir a UI**: `https://<ip-do-LXC>:8443`. O certificado é autoassinado (`/etc/pve-patcher/tls`, gerado pelo
   `deploy/lxc/tls-selfsigned.sh`): confira no navegador o SHA-256 que o `install.sh` imprime. A 8080 só redireciona.
   - **Atrás de um proxy (opcional)**: aponte para `https://<ip-do-LXC>:8443`, com `proxy_ssl_verify off` ou
     confiando no `cert.pem`, e com WebSocket, que o Blazor Server exige. Defina `Bootstrap:PublicBaseUrl` com a URL
     do proxy e `Bootstrap:PinAppCertificate: false` se o proxy tiver certificado válido. **Inclua a faixa dos
     navegadores e a das VMs (para o `curl` do bootstrap) na IP ACL**, senão a UI ou o bootstrap respondem 403. O
     app respeita `X-Forwarded-For/Proto/Host`.
   - **Trocar o certificado**: substitua `cert.pem`/`key.pem` (PEM) e rode `systemctl restart pve-patcher`.
     Para renovar o autoassinado, use `sh deploy/lxc/tls-selfsigned.sh --force`. O pin do comando de bootstrap muda junto.
10. Clique em **Descobrir agora** e depois **Escanear todas**.

### Firewall

| Origem | Destino | Porta | Uso |
|---|---|---|---|
| LXC pve-patcher | nós do PVE | TCP 8006 | API do PVE (token de serviço e login dos usuários) |
| LXC pve-patcher | VMs | TCP 22 (ou a porta SSH da VM) | SSH sem agente |
| Navegadores / proxy | LXC pve-patcher | TCP 8443 | UI (HTTPS); a 8080 só redireciona |
| VMs | LXC pve-patcher (ou proxy) | TCP 8443 | Só o `curl` do bootstrap, uma vez por VM |

### Bootstrap do primeiro cluster

Sem cluster cadastrado ninguém consegue logar. Por isso `Bootstrap:Clusters` (em `appsettings.json` ou, em produção,
`/etc/pve-patcher/appsettings.Production.json`) semeia o banco na inicialização, se o `Id` ainda não existir:

```json
{
  "Bootstrap": {
    "PublicBaseUrl": "",
    "PinAppCertificate": true,
    "Clusters": [
      { "Id": "prod", "Name": "Produção", "Endpoints": ["https://172.22.1.10:8006"], "CertFingerprintSha256": "AA:BB:..." }
    ]
  }
}
```

Depois disso os clusters se gerenciam na UI (CRUD, testar conexão = discovery dry-run; com 0 VMs ou sem resposta do guest agent, o teste consulta as permissões do token e diz o que falta). O token do cluster **não** vai
neste arquivo: é escrito no cofre (passo 6).

## Permissões do Proxmox por tela

O login é feito com a conta do usuário no PVE (`user@realm`, com TOTP quando exigido); a senha nunca é guardada. As
permissões vêm de `GET /access/permissions` do cluster **em que o usuário logou** e valem por 8 h (sessão em memória:
reiniciar o serviço encerra as sessões).

| Ação | Privilégio exigido |
|---|---|
| Entrar, ver visão geral, VMs, CVEs e fila | `Sys.Audit` em `/` |
| Escanear, atualizar, trocar IP/porta SSH, aceitar host key, cancelar job de uma VM | `VM.PowerMgmt` em `/vms/{vmid}` (ou herdado de `/vms` ou `/`) |
| Configurações, clusters, segredos, atualizar base de CVEs | `Sys.Modify` em `/` |
| Terminal SSH e arquivos (SFTP) | só estar logado: o acesso é decidido pela conta SSH do terminal na VM, não pelo PVE |

**Limitação multi-cluster:** as permissões são só do cluster do login. Para VMs de **outro** cluster o usuário não tem
permissão e a UI as mostra em somente leitura; para operá-las, faça login naquele cluster. As mesmas regras são
verificadas no servidor, não só na UI.

## Terminal SSH

Um terminal no navegador, no estilo do PuTTY, para qualquer VM do inventário. Ele abre pelo menu **Terminal ↗**, pelo
botão na tela da VM ou pelo botão **SSH ↗** de cada linha da visão geral, sempre numa aba nova do navegador.

- **Credencial própria**: uma segunda chave, `ssh/console` no cofre, usada só aqui, e um **usuário fixo** igual para
  todas as VMs. Configure ambos em *Configurações > Terminal SSH*:
  - gere um par ed25519 ou cole uma chave existente;
  - o certificado OpenSSH (`-cert.pub`) é opcional; a tela confere se a chave, a passphrase e o certificado batem
    antes de gravar.
- **Preparo da conta**: *Configurações > Terminal SSH* mostra um segundo comando de bootstrap, para rodar como root em
  cada VM (mesma URL e certificado do primeiro):
  `curl … https://<este-host>:8443/bootstrap-console.sh | sh -s -- --pubkey '<chave pública do terminal>' --user '<usuário>'`.
  O script (`deploy/target/bootstrap-console.sh`) é idempotente e **não cria o usuário**: a conta precisa existir (local ou
  LDAP/SSSD). Ele confere cada item, imprime `ok:`, `ajustado:` ou `AVISO:` e corrige só o que faltar:
  - chave no `~/.ssh/authorized_keys`: adiciona a que falta e regrava sem `no-pty`/`restrict`/`command=`, porque o terminal precisa de PTY;
  - permissões do home (sem escrita para grupo/outros), do `~/.ssh` (700) e do `authorized_keys` (600);
  - conta sem senha bloqueada (`!` no shadow vira `*`);
  - sudo: testa `sudo -n` como o usuário e, se pedir senha, grava `/etc/sudoers.d/zz-pve-patcher-console` com
    `NOPASSWD: ALL` (validado com `visudo`). **O terminal passa a ter root sem senha nessa conta**;
  - shell `nologin` e configuração do sshd (`PubkeyAuthentication`, `AllowUsers/AllowGroups`, `AuthorizedKeysFile`,
    `PermitRootLogin` para root): só avisa.

  Com `root` (o padrão) ele só confere a chave e o sshd. Uma alternativa ao script é confiar na sua CA (`TrustedUserCAKeys`).
  O usuário `patcher` do primeiro bootstrap **não** serve: ele tem `no-pty` e sudo restrito.
- **Host key**: a mesma do patcher (TOFU na primeira conexão). Se a host key mudar, o terminal fica bloqueado até
  alguém aceitar a nova chave na tela da VM.
- **Recursos**:
  - várias abas e Reconectar;
  - cores e redimensionamento (PTY `xterm-256color`);
  - copiar ao selecionar e colar com o botão direito, como no PuTTY; também Ctrl+Shift+C/V e Shift+Insert. O clipboard exige HTTPS;
  - aparência (fonte, tamanho, tema, scrollback), salva no navegador;
  - painel **Arquivos** (SFTP): navegar, baixar, enviar com progresso, criar pasta, renomear e apagar.
- **Acesso**: qualquer usuário logado no app (não depende de privilégio do PVE). Cada sessão e operação de arquivo vai
  para o journal: `journalctl -u pve-patcher | grep -E 'Terminal|SFTP'` (usuário do app, VM, conta SSH, duração e bytes).
- **Limites** (seção `Console` do appsettings): `MaxSessionsPerUser` (10), `MaxSessions` (50), `MaxUploadMegabytes` (2048).
- **Atrás de proxy**: o terminal usa WebSocket em `/terminal/ws` (ping a cada 30 s). Use `proxy_read_timeout` alto e
  `client_max_body_size` compatível com os uploads.

## Operação

- **Após reiniciar o LXC o cofre volta selado**: rode o unseal (`deploy/openbao/unseal.sh`; o `install.sh` o instala como
  `pve-patcher-unseal`). Enquanto isso o banner vermelho aparece e os jobs falham sem derrubar o app.
- Logs: `journalctl -u pve-patcher -f`. Dados: `/var/lib/pve-patcher` (basta copiar `state.db` para backup, mas é
  estado reconstruível por um scan). As chaves do cookie ficam em `/var/lib/pve-patcher/keys`.
- Atualizar o app: novo `publish.ps1`, extrair no LXC e `sh deploy/lxc/install.sh --skip-openbao` (preserva a configuração).
  O `deploy.ps1` faz tudo isso no LXC padrão (`root@172.22.104.31`, chave `C:\Users\heber\keys\minetto`; troque com
  `-TargetHost`, `-User`, `-Key`): publica, envia como `~/pve-patcher-<data><letra>.tar.gz`, extrai em
  `~/release-<data><letra>` e instala. `-SkipPublish` reenvia o pacote já gerado.
- Globalização invariante (sem `libicu`); o fuso do agendador exige `tzdata` (instalado pelo `install.sh`).

## Desenvolvimento

```
dotnet build src/PvePatcher.Web
ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/PvePatcher.Web
```

Com `Dev:UseFakes=true` (padrão em `appsettings.Development.json`) a UI roda sem PVE, cofre ou VMs: 2 clusters
(`prod`, `lab`), 8 VMs de várias distros, CVEs com KEV/críticas e um upgrade simulado com log ao vivo. Login: qualquer
usuário com a senha `dev` (`root@pam` tem tudo; `viewer@pve` só vê; `ops@pve` opera só as VMs 101 e 102;
`totp@pve` pede o código `123456`). O banco de desenvolvimento fica em `src/PvePatcher.Web/devdata/`.

Testes: `dotnet test tests/PvePatcher.Web.Tests`.

## Limitações

- Estado atual apenas: sem histórico de scans, CVEs ou upgrades.
- Sessões em memória (reiniciar o serviço exige novo login); permissões não são reconsultadas durante a sessão de 8 h.
- Um job por vez: ciclos longos em frotas grandes são sequenciais por projeto.
- Upgrade em andamento não pode ser cancelado (scans podem).
- A chave SSH por VM (`ssh/vm/{cluster}/{vmid}`) é respeitada se existir no cofre, mas só a padrão tem tela.
- Só QEMU; templates são ignorados.
