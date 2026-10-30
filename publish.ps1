# Gera publish/pve-patcher.tar.gz (binários self-contained linux-x64 + deploy/) para instalar no LXC.
# Uso:  .\publish.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$dotnet = if (Get-Command dotnet -ErrorAction SilentlyContinue) { 'dotnet' } else { Join-Path $env:USERPROFILE '.dotnet\dotnet.exe' }

$out = Join-Path $root 'publish'
$stage = Join-Path $out 'stage'
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $stage 'pve-patcher') | Out-Null

& $dotnet publish (Join-Path $root 'src\PvePatcher.Web') -c Release -r linux-x64 --self-contained -p:PublishSingleFile=false -o (Join-Path $stage 'pve-patcher')
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish falhou' }

# Mantém também o diretório publicado puro (pedido original): publish/pve-patcher
$plain = Join-Path $out 'pve-patcher'
if (Test-Path $plain) { Remove-Item $plain -Recurse -Force }
Copy-Item (Join-Path $stage 'pve-patcher') $plain -Recurse

# deploy/ com finais de linha LF (os scripts rodam no Linux)
$deployDst = Join-Path $stage 'deploy'
Copy-Item (Join-Path $root 'deploy') $deployDst -Recurse
Get-ChildItem $deployDst -Recurse -File | Where-Object { $_.Extension -in '.sh', '.service', '.hcl' -or $_.Name -in 'patcher-agent', 'patcher-upgrade' } | ForEach-Object {
    $text = [IO.File]::ReadAllText($_.FullName) -replace "`r`n", "`n"
    [IO.File]::WriteAllText($_.FullName, $text, (New-Object Text.UTF8Encoding($false)))
}

$tar = Join-Path $out 'pve-patcher.tar.gz'
if (Test-Path $tar) { Remove-Item $tar -Force }
& (Join-Path $env:SystemRoot 'System32\tar.exe') -czf $tar -C $stage pve-patcher deploy
if ($LASTEXITCODE -ne 0) { throw 'tar falhou' }
Remove-Item $stage -Recurse -Force

Write-Host "Pronto: $tar"
Write-Host 'No LXC:  tar xzf pve-patcher.tar.gz && sh deploy/lxc/install.sh'
