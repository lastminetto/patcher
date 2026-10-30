# Publica e instala o app no LXC: publish.ps1, envia o tarball como ~/pve-patcher-<data><letra>.tar.gz, extrai em
# ~/release-<data><letra> e roda deploy/lxc/install.sh --skip-openbao (preserva configuração e cofre).
# Uso:  .\deploy.ps1                 (publica e instala no LXC padrão)
#       .\deploy.ps1 -SkipPublish    (reenvia o publish/pve-patcher.tar.gz já gerado)
param(
    [string]$TargetHost = '172.22.104.31',
    [string]$User = 'root',
    [string]$Key = 'C:\Users\heber\keys\minetto',
    [switch]$SkipPublish
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot

# ssh/scp: OpenSSH do Windows ou o do Git.
function Find-Tool([string]$name) {
    $c = Get-Command $name -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($dir in @("$env:SystemRoot\System32\OpenSSH", "$env:ProgramFiles\Git\usr\bin")) {
        $p = Join-Path $dir "$name.exe"
        if (Test-Path $p) { return $p }
    }
    throw "$name não encontrado (instale o OpenSSH Client ou o Git for Windows)"
}
$ssh = Find-Tool 'ssh'
$scp = Find-Tool 'scp'
if (-not (Test-Path $Key)) { throw "Chave SSH não encontrada: $Key" }
$opts = @('-i', $Key, '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=15')
$dest = "$User@$TargetHost"

if (-not $SkipPublish) {
    & (Join-Path $root 'publish.ps1')
}
$tar = Join-Path $root 'publish\pve-patcher.tar.gz'
if (-not (Test-Path $tar)) { throw "Pacote não encontrado: $tar (rode sem -SkipPublish)" }

# Nome da release: data de hoje + letra seguinte às já existentes no LXC (20261015, 20261015b, 20261015c...).
$date = Get-Date -Format 'yyyyMMdd'
$count = [int](& $ssh @opts $dest "ls -d ~/release-$date* 2>/dev/null | wc -l")
if ($LASTEXITCODE -ne 0) { throw "Sem acesso SSH a $dest" }
$name = if ($count -eq 0) { $date } else { $date + [char](97 + $count) }
Write-Host "Release $name -> $dest"

& $scp @opts $tar "${dest}:pve-patcher-$name.tar.gz"
if ($LASTEXITCODE -ne 0) { throw 'scp falhou' }

$remote = "set -e; cd ~; mkdir release-$name; tar xzf pve-patcher-$name.tar.gz -C release-$name; " +
          "sh release-$name/deploy/lxc/install.sh --skip-openbao; sleep 3; systemctl is-active pve-patcher"
& $ssh @opts $dest $remote
if ($LASTEXITCODE -ne 0) { throw "Instalação falhou (veja: ssh $dest journalctl -u pve-patcher -n 100)" }
Write-Host "Instalado: release-$name em $TargetHost"
