# OpenBao do pve-patcher: nó único, só acessível localmente (o app roda no mesmo LXC).

ui = false

# OpenBao 2.x não tem mais o storage "file" (nem disable_mlock): o suportado é o raft integrado,
# aqui com um nó só. Backup consistente: `bao operator raft snapshot save` (dados seguem cifrados;
# sem as chaves de unseal não servem para nada).
storage "raft" {
  path    = "/var/lib/openbao"
  node_id = "pve-patcher"
}

# Sem TLS de propósito: escuta só em loopback. Se um dia expuser na rede, ponha TLS aqui.
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"

log_level = "info"
