# OpenBao do pve-patcher: nó único, só acessível localmente (o app roda no mesmo LXC).

ui = false

# Armazenamento em arquivos. Backup consistente = parar o serviço e copiar /var/lib/openbao
# (os dados continuam cifrados; sem as chaves de unseal não servem para nada).
storage "file" {
  path = "/var/lib/openbao"
}

# Sem TLS de propósito: escuta só em loopback. Se um dia expuser na rede, ponha TLS aqui.
listener "tcp" {
  address         = "127.0.0.1:8200"
  tls_disable     = true
}

api_addr = "http://127.0.0.1:8200"

# mlock impede que a memória do processo (onde ficam as chaves) vá para swap. Num LXC sem
# privilégios o mlock costuma falhar (sem CAP_IPC_LOCK / RLIMIT_MEMLOCK baixo) e o serviço nem
# inicia, então desligamos. Mitigação: manter o LXC sem swap (swap = 0 no Proxmox).
disable_mlock = true

log_level = "info"
