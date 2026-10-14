# pve-patcher

Aplicação web (LXC no Proxmox) que descobre as VMs QEMU dos clusters, entra por SSH, lista as atualizações
pendentes, cruza com CVEs (com criticidade, KEV e EPSS) e atualiza sob comando, uma VM por vez.

Distros suportadas nas VMs: Debian, Ubuntu, AlmaLinux/Rocky e Alpine. Só VMs QEMU (sem containers LXC).

## Arquitetura

```
 Navegador ──HTTPS──> nginx (OPNsense) ──HTTP──> LXC pve-patcher :8080
                                                  ├─ PvePatcher.Web  (Blazor Server, SQLite, fila, agendador)
                                                  ├─ OpenBao 127.0.0.1:8200 (token PVE, chave SSH, chave NVD)
                                                  └─> API do PVE (token de serviço)  /  SSH nas VMs (chave do cofre)
```

| Projeto | Função |
|---|---|
| `PvePatcher.Core` | Contratos (interfaces e records) |
| `PvePatcher.Integrations` | OpenBao, cliente da API do PVE, login via PVE, escolha de IP |
| `PvePatcher.Targets` | SSH, scan e upgrade nas VMs (`patcher-agent`) |
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
8. **Preparar as VMs** (como root em cada VM): `curl -fsSL http://<este-host>:8080/bootstrap-vm.sh | sh -s -- --pubkey '<chave pública>'`.
   Cria o usuário `patcher`, instala o `patcher-agent` e um sudoers restrito a ele. O endpoint (gerado por `PvePatcher.Targets.BootstrapScript`, com o agent embutido) é anônimo (só serve o
   script, sem segredos). Defina `Bootstrap:PublicBaseUrl` se a VM alcança o LXC por outro endereço que o da UI.
9. **Abrir a UI pelo nginx do OPNsense**: proxy para `http://<ip-do-LXC>:8080` (com WebSocket, necessário ao Blazor
   Server). **Inclua a faixa do LXC e a dos clientes (as VMs, para o `curl` do bootstrap) na IP ACL do nginx**, senão a UI
   ou o bootstrap respondem 403. O app respeita `X-Forwarded-For/Proto/Host`.
10. Clique em **Descobrir agora** e depois **Escanear todas**.

### Bootstrap do primeiro cluster

Sem cluster cadastrado ninguém consegue logar. Por isso `Bootstrap:Clusters` (em `appsettings.json` ou, em produção,
`/etc/pve-patcher/appsettings.Production.json`) semeia o banco na inicialização, se o `Id` ainda não existir:

```json
{
  "Bootstrap": {
    "PublicBaseUrl": "http://172.22.20.50:8080",
    "Clusters": [
      { "Id": "prod", "Name": "Produção", "Endpoints": ["https://172.22.1.10:8006"], "CertFingerprintSha256": "AA:BB:..." }
    ]
  }
}
```

Depois disso os clusters se gerenciam na UI (CRUD, testar conexão = discovery dry-run). O token do cluster **não** vai
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

**Limitação multi-cluster:** as permissões são só do cluster do login. Para VMs de **outro** cluster o usuário não tem
permissão e a UI as mostra em somente leitura; para operá-las, faça login naquele cluster. As mesmas regras são
verificadas no servidor, não só na UI.

## Operação

- **Após reiniciar o LXC o cofre volta selado**: rode o unseal (`deploy/openbao/unseal.sh`; o `install.sh` o instala como
  `pve-patcher-unseal`). Enquanto isso o banner vermelho aparece e os jobs falham sem derrubar o app.
- Logs: `journalctl -u pve-patcher -f`. Dados: `/var/lib/pve-patcher` (basta copiar `state.db` para backup, mas é
  estado reconstruível por um scan). As chaves do cookie ficam em `/var/lib/pve-patcher/keys`.
- Atualizar o app: novo `publish.ps1`, extrair no LXC e `sh deploy/lxc/install.sh --skip-openbao` (preserva a configuração).
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
