param(
    [switch]$Run
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $projectRoot 'IpsecWatch\Program.cs'
$manifest = Join-Path $projectRoot 'IpsecWatch\app.manifest'
$outputDir = Join-Path $projectRoot 'dist'
$output = Join-Path $outputDir 'IpsecWatch.exe'
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'

if (-not (Test-Path -LiteralPath $compiler)) {
    $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path -LiteralPath $compiler)) {
    throw 'Compilador C# do .NET Framework não encontrado.'
}

New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
& $compiler /nologo /target:winexe /optimize+ /platform:anycpu /win32manifest:$manifest `
    /reference:System.dll /reference:System.Core.dll /reference:System.Drawing.dll `
    /reference:System.Windows.Forms.dll /reference:System.Xml.dll `
    /out:$output $source

if ($LASTEXITCODE -ne 0) {
    throw "Falha na compilação (código $LASTEXITCODE)."
}

Write-Host "Criado: $output"
if ($Run) {
    Start-Process -FilePath $output -Verb RunAs
}
