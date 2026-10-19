# Gera o pacote para distribuir: empacotar\DPS-Meter-BDO.zip
# Uso (na pasta do projeto, com o ambiente .venv criado):  powershell -File empacotar\build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"

Push-Location $root
& $py -m PyInstaller --noconfirm --onedir --windowed --name DPSMeterBDO `
    --icon (Join-Path $root "empacotar\bdometer.ico") `
    --collect-all scapy --hidden-import PIL._tkinter_finder `
    --distpath empacotar/dist --workpath empacotar/build --specpath empacotar meter.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falhou" }
Pop-Location

# Pasta final com o LEIA-ME, compactada num .zip
$stage = Join-Path $root "empacotar\dist\DPS-Meter-BDO"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
Move-Item (Join-Path $root "empacotar\dist\DPSMeterBDO") $stage
Copy-Item (Join-Path $root "empacotar\LEIA-ME.txt") $stage

$zip = Join-Path $root "empacotar\DPS-Meter-BDO.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path $stage -DestinationPath $zip
Write-Host "Pacote pronto: $zip"
