#requires -Version 5.1
# ==============================================================================
# NOX RP - Security & Service Integrity PRE-CHECK
# Desenvolvido por: Nev3rFlame
#
# Esta ferramenta e apenas um pre-check informativo e de leitura.
# Nao altera servicos, registo, politicas, ficheiros ou configuracoes do Windows.
# Nao deteta cheats e nao substitui o PC Check realizado pela Staff.
# ==============================================================================

# Identidade codificada em hexadecimal. O checksum 947 confirma apenas o texto do autor;
# nao e uma assinatura criptografica nem protege as restantes funcoes do script.
$ServerName = -join [char[]]@(0x4E,0x4F,0x58,0x20,0x52,0x50)
$Author = -join [char[]]@(0x4E,0x65,0x76,0x33,0x72,0x46,0x6C,0x61,0x6D,0x65)

function Get-TextChecksum {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sum = 0
    foreach ($character in $Text.ToCharArray()) {
        $sum += [int][char]$character
    }
    return $sum
}

$BrandingValid = (
    $ServerName.Length -eq 6 -and (Get-TextChecksum -Text $ServerName) -eq 439 -and
    $Author.Length -eq 10 -and (Get-TextChecksum -Text $Author) -eq 947
)

if (-not $BrandingValid) {
    Write-Host '[ERRO] O marcador de identidade NOX RP / Nev3rFlame nao corresponde ao esperado.' -ForegroundColor Red
    Write-Host 'Esta verificacao e apenas um controlo de identidade textual, nao uma protecao criptografica.' -ForegroundColor Yellow
    return
}

$RequiredServices = @(
    'PcaSvc',
    'DPS',
    'DiagTrack',
    'EventLog',
    'SysMain',
    'Schedule',
    'DusmSvc',
    'Appinfo',
    'WSearch'
)

try {
    $Host.UI.RawUI.WindowTitle = "$ServerName | Security Guard - by $Author"
} catch {
    # Alguns hosts PowerShell nao disponibilizam WindowTitle.
}

function New-CheckResult {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Detail,
        [int]$Code
    )

    [pscustomobject]@{
        Name   = $Name
        Status = $Status
        Detail = $Detail
        Code   = $Code # 0 = confirmado; 1 = pendente; 2 = requisito em falta
    }
}

function Format-Duration {
    param([TimeSpan]$Duration)

    if ($Duration.TotalDays -ge 1) {
        return ('{0}d {1}h' -f [int][Math]::Floor($Duration.TotalDays), $Duration.Hours)
    }
    if ($Duration.TotalHours -ge 1) {
        return ('{0}h {1:D2}m' -f [int][Math]::Floor($Duration.TotalHours), $Duration.Minutes)
    }
    return ('{0}m' -f [int][Math]::Floor($Duration.TotalMinutes))
}

function Get-StatusColor {
    param([int]$Code)

    switch ($Code) {
        0 { return [ConsoleColor]::Green }
        1 { return [ConsoleColor]::Yellow }
        default { return [ConsoleColor]::Red }
    }
}

function Get-ServiceAudit {
    param([string[]]$ServiceNames)

    try {
        # Uma unica consulta evita varias chamadas CIM e nao inicia nem altera servicos.
        $allServices = @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)
    } catch {
        $unreadable = foreach ($serviceName in $ServiceNames) {
            New-CheckResult -Name $serviceName -Status 'SEM LEITURA' `
                -Detail 'O Windows nao permitiu consultar este servico.' -Code 1
        }
        return $unreadable
    }

    $results = foreach ($serviceName in $ServiceNames) {
        $service = $allServices | Where-Object { $_.Name -eq $serviceName } | Select-Object -First 1

        if ($null -eq $service) {
            New-CheckResult -Name $serviceName -Status 'INEXISTENTE' `
                -Detail 'O servico nao foi encontrado nesta instalacao do Windows.' -Code 2
            continue
        }

        $startLabel = switch -Exact ($service.StartMode) {
            'Auto'     { 'Automatico' }
            'Manual'   { 'Manual / acionamento' }
            'Disabled' { 'Desativado' }
            default    { [string]$service.StartMode }
        }

        if ($service.StartMode -eq 'Disabled') {
            New-CheckResult -Name $serviceName -Status 'DESATIVADO' `
                -Detail ("Arranque: {0}. O servico esta configurado como desativado." -f $startLabel) -Code 2
        }
        elseif ($service.State -eq 'Running') {
            New-CheckResult -Name $serviceName -Status 'ATIVO' `
                -Detail ("Arranque: {0}." -f $startLabel) -Code 0
        }
        elseif ($service.StartMode -eq 'Manual') {
            New-CheckResult -Name $serviceName -Status 'PARADO / MANUAL' `
                -Detail ("O servico nao esta em execucao e esta em modo manual/acionado. Confirmacao da Staff recomendada.") -Code 1
        }
        else {
            New-CheckResult -Name $serviceName -Status 'PARADO' `
                -Detail ("Estado: {0} | Arranque: {1}. A regra atual do pre-check exige que esteja em execucao." -f $service.State, $startLabel) -Code 2
        }
    }

    return $results
}

function Test-MemoryIntegrity {
    try {
        $deviceGuard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' `
            -ClassName Win32_DeviceGuard -ErrorAction Stop

        if ($null -eq $deviceGuard) {
            return (New-CheckResult -Name 'Integridade da memoria (HVCI)' -Status 'SEM LEITURA' `
                -Detail 'O Windows nao devolveu dados do Device Guard.' -Code 1)
        }

        $isRunning = @($deviceGuard.SecurityServicesRunning) -contains 2
        if ($isRunning) {
            return (New-CheckResult -Name 'Integridade da memoria (HVCI)' -Status 'ATIVA' `
                -Detail 'O Windows confirma que a Integridade da memoria esta em execucao.' -Code 0)
        }

        $isConfigured = @($deviceGuard.SecurityServicesConfigured) -contains 2
        if ($isConfigured) {
            return (New-CheckResult -Name 'Integridade da memoria (HVCI)' -Status 'PENDENTE' `
                -Detail 'Esta configurada, mas ainda nao aparece em execucao. Pode ser necessario reiniciar.' -Code 1)
        }

        return (New-CheckResult -Name 'Integridade da memoria (HVCI)' -Status 'DESATIVADA' `
            -Detail 'O Windows nao indica a Integridade da memoria como configurada ou em execucao.' -Code 2)
    } catch {
        return (New-CheckResult -Name 'Integridade da memoria (HVCI)' -Status 'SEM LEITURA' `
            -Detail 'Nao foi possivel consultar o estado do Device Guard.' -Code 1)
    }
}

function Test-DriverBlocklist {
    param(
        [int]$BuildNumber,
        [bool]$MemoryIntegrityRunning
    )

    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'
    $valueName = 'VulnerableDriverBlocklistEnable'

    try {
        $registryPathExists = Test-Path -LiteralPath $registryPath -ErrorAction Stop
    } catch {
        return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'SEM LEITURA' `
            -Detail 'Nao foi possivel confirmar se a chave de configuracao existe.' -Code 1)
    }

    if ($registryPathExists) {
        try {
            $keyProperties = Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop
            $valueProperty = $keyProperties.PSObject.Properties[$valueName]

            if ($null -ne $valueProperty -and $null -ne $valueProperty.Value) {
                $value = [int]$valueProperty.Value

                if ($value -eq 1) {
                    return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'ATIVA' `
                        -Detail 'O valor de configuracao do Windows esta definido como ativo.' -Code 0)
                }
                if ($value -eq 0) {
                    return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'DESATIVADA' `
                        -Detail 'O valor de configuracao do Windows esta definido como desativado.' -Code 2)
                }

                return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'SEM LEITURA' `
                    -Detail ("Foi encontrado um valor nao reconhecido ({0}). Confirmacao manual necessaria." -f $value) -Code 1)
            }
        } catch {
            return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'SEM LEITURA' `
                -Detail 'Nao foi possivel ler a configuracao no Registo.' -Code 1)
        }
    }

    # A Microsoft indica que a blocklist esta ativa por predefinicao no Windows 11 22H2+
    # e tambem e aplicada quando a Integridade da memoria (HVCI) esta em execucao.
    if ($BuildNumber -ge 22621) {
        return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'ATIVA POR PREDEFINICAO' `
            -Detail 'Windows 11 22H2 ou posterior; nao foi encontrado um valor explicito a desativar a funcionalidade.' -Code 0)
    }

    if ($MemoryIntegrityRunning) {
        return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'ATIVA COM HVCI' `
            -Detail 'A HVCI esta em execucao; a Microsoft indica que a blocklist tambem e aplicada neste caso.' -Code 0)
    }

    return (New-CheckResult -Name 'Lista de bloqueio de drivers vulneraveis' -Status 'CONFIRMACAO PENDENTE' `
        -Detail 'Nao existe um valor explicito e nao foi possivel confirmar a ativacao pelas predefinicoes conhecidas. Confirma na Seguranca do Windows.' -Code 1)
}

function Test-SecureBoot {
    $registryPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
    $valueName = 'UEFISecureBootEnabled'

    try {
        $state = Get-ItemProperty -LiteralPath $registryPath -Name $valueName -ErrorAction Stop
        $value = [int]$state.$valueName

        if ($value -eq 1) {
            return (New-CheckResult -Name 'Arranque seguro (Secure Boot)' -Status 'ATIVO' `
                -Detail 'O estado registado pelo Windows indica Secure Boot ativo.' -Code 0)
        }
        if ($value -eq 0) {
            return (New-CheckResult -Name 'Arranque seguro (Secure Boot)' -Status 'DESATIVADO' `
                -Detail 'O estado registado pelo Windows indica Secure Boot desativado.' -Code 2)
        }

        return (New-CheckResult -Name 'Arranque seguro (Secure Boot)' -Status 'SEM LEITURA' `
            -Detail 'O Windows devolveu um valor inesperado para Secure Boot.' -Code 1)
    } catch {
        return (New-CheckResult -Name 'Arranque seguro (Secure Boot)' -Status 'SEM LEITURA' `
            -Detail 'Nao foi possivel confirmar o estado UEFI. A Staff deve validar manualmente, por exemplo atraves de msinfo32/firmware.' -Code 1)
    }
}

function Test-Tpm20 {
    try {
        $tpmInfo = Get-Tpm -ErrorAction Stop
    } catch {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'SEM LEITURA' `
            -Detail 'O comando Get-Tpm nao esta disponivel ou o Windows nao permitiu consultar o TPM.' -Code 1)
    }

    if ($null -eq $tpmInfo -or -not $tpmInfo.TpmPresent) {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'NAO DETETADO' `
            -Detail 'O Windows nao detetou um TPM.' -Code 2)
    }

    try {
        $tpmCim = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftTpm' `
            -ClassName Win32_Tpm -ErrorAction Stop
    } catch {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'SEM LEITURA' `
            -Detail 'O TPM foi detetado, mas nao foi possivel consultar a versao da especificacao.' -Code 1)
    }

    if ($null -eq $tpmCim) {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'SEM LEITURA' `
            -Detail 'O Windows nao devolveu a classe Win32_Tpm para confirmar a versao.' -Code 1)
    }

    $specVersion = [string]$tpmCim.SpecVersion
    $majorVersion = ($specVersion -split ',')[0].Trim()

    if ($majorVersion -ne '2.0') {
        if ([string]::IsNullOrWhiteSpace($specVersion) -or $specVersion -eq 'Not Supported') {
            return (New-CheckResult -Name 'TPM 2.0' -Status 'SEM LEITURA' `
                -Detail 'A versao da especificacao do TPM nao foi disponibilizada.' -Code 1)
        }

        return (New-CheckResult -Name 'TPM 2.0' -Status 'VERSAO INCOMPATIVEL' `
            -Detail ("Foi detetada a especificacao TPM {0}; e exigida a versao 2.0." -f $specVersion) -Code 2)
    }

    if ($tpmInfo.RestartPending -eq $true) {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'REINICIO PENDENTE' `
            -Detail 'O TPM 2.0 foi detetado, mas o Windows indica que existe uma operacao pendente de reinicio.' -Code 1)
    }

    if ($tpmInfo.TpmReady -eq $true) {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'ATIVO E PRONTO' `
            -Detail ("Especificacao {0}; TPM presente e pronto para utilizacao." -f $specVersion) -Code 0)
    }

    if ($tpmInfo.TpmReady -eq $false) {
        return (New-CheckResult -Name 'TPM 2.0' -Status 'NAO PRONTO' `
            -Detail 'O TPM 2.0 foi detetado, mas o Windows indica que ainda nao esta pronto para utilizacao.' -Code 2)
    }

    return (New-CheckResult -Name 'TPM 2.0' -Status 'SEM LEITURA' `
        -Detail 'Foi detetado um TPM 2.0, mas nao foi possivel confirmar se esta pronto.' -Code 1)
}

function Write-PanelTitle {
    param([string]$Title)

    Write-Host ''
    Write-Host ('  +-' + ('-' * 68) + '-+') -ForegroundColor DarkMagenta
    Write-Host ('  | {0,-68} |' -f $Title) -ForegroundColor Magenta
    Write-Host ('  +-' + ('-' * 68) + '-+') -ForegroundColor DarkMagenta
}

function Write-CheckLine {
    param([psobject]$Result, [string]$Prefix = '  ')

    $color = Get-StatusColor -Code $Result.Code
    $tag = switch ($Result.Code) {
        0 { '[ OK ]' }
        1 { '[ ?  ]' }
        default { '[ !! ]' }
    }

    Write-Host ($Prefix + $tag + ' ') -NoNewline -ForegroundColor $color
    Write-Host $Result.Name -ForegroundColor White
    if (-not [string]::IsNullOrWhiteSpace($Result.Detail)) {
        Write-Host ($Prefix + '       ' + $Result.Detail) -ForegroundColor DarkGray
    }
}

function Show-PreCheck {
    try { Clear-Host } catch { }

    $now = Get-Date
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    } catch {
        Write-Host '[ERRO] Nao foi possivel consultar as informacoes do Windows.' -ForegroundColor Red
        return
    }

    $bootTime = [datetime]$os.LastBootUpTime
    $uptime = $now - $bootTime
    $buildNumber = 0
    [void][int]::TryParse([string]$os.BuildNumber, [ref]$buildNumber)

    $serviceResults = @(Get-ServiceAudit -ServiceNames $RequiredServices)
    $memoryResult = Test-MemoryIntegrity
    $blocklistResult = Test-DriverBlocklist -BuildNumber $buildNumber `
        -MemoryIntegrityRunning ($memoryResult.Code -eq 0)
    $securityResults = @(
        $memoryResult,
        $blocklistResult,
        (Test-SecureBoot),
        (Test-Tpm20)
    )

    $allResults = @($serviceResults) + @($securityResults)
    $failedCount = @($allResults | Where-Object { $_.Code -eq 2 }).Count
    $pendingCount = @($allResults | Where-Object { $_.Code -eq 1 }).Count
    $passedCount = @($allResults | Where-Object { $_.Code -eq 0 }).Count
    $totalCount = $allResults.Count
    $barWidth = 30
    $barFilled = 0
    if ($totalCount -gt 0) {
        $barFilled = [int][Math]::Round(($passedCount / $totalCount) * $barWidth, 0)
    }
    $progressBar = ('#' * $barFilled) + ('.' * ($barWidth - $barFilled))

    # Header principal
    Write-Host ''
    Write-Host ('  ' + ('=' * 72)) -ForegroundColor DarkMagenta
    Write-Host '                         N O X   R P' -ForegroundColor Magenta
    Write-Host '                    SECURITY GUARD  |  PRE-CHECK' -ForegroundColor White
    Write-Host ('                Desenvolvido por: {0}' -f $Author) -ForegroundColor DarkMagenta
    Write-Host ('  ' + ('=' * 72)) -ForegroundColor DarkMagenta

    # Informacao do computador
    Write-Host ('  WINDOWS   {0}  (Build {1})' -f $os.Caption, $os.BuildNumber) -ForegroundColor Gray
    Write-Host ('  DATA      {0:dd/MM/yyyy  HH:mm:ss}' -f $now) -ForegroundColor Gray
    Write-Host ('  LIGADO    {0}' -f (Format-Duration $uptime)) -ForegroundColor Gray

    # Auditoria dos servicos
    Write-PanelTitle -Title '01  |  SERVICOS DO WINDOWS'
    $index = 1
    foreach ($result in $serviceResults) {
        $number = '[{0:D2}]' -f $index
        Write-Host ('  ' + $number + ' ') -NoNewline -ForegroundColor DarkMagenta
        Write-CheckLine -Result $result -Prefix '  '
        $index++
    }

    # Seguranca
    Write-PanelTitle -Title '02  |  SEGURANCA DO WINDOWS'
    foreach ($result in $securityResults) {
        Write-CheckLine -Result $result -Prefix '  '
    }

    # Resumo
    Write-PanelTitle -Title '03  |  RESULTADO DO PRE-CHECK'
    Write-Host ('  PROGRESSO  [{0}]  {1}/{2} confirmados' -f $progressBar, $passedCount, $totalCount) -ForegroundColor Magenta
    Write-Host ('  ESTADOS    {0} aprovados  |  {1} pendentes  |  {2} em falta' -f `
        $passedCount, $pendingCount, $failedCount) -ForegroundColor Gray
    Write-Host ''

    if ($failedCount -gt 0) {
        Write-Host '  [ !! ]  REQUISITOS EM FALTA' -ForegroundColor Red
        Write-Host '         Consulta os itens assinalados a vermelho e segue as instrucoes oficiais.' -ForegroundColor Yellow
    }
    elseif ($pendingCount -gt 0) {
        Write-Host '  [ ?? ]  VERIFICACAO PENDENTE' -ForegroundColor Yellow
        Write-Host '         Existem itens que nao puderam ser confirmados automaticamente.' -ForegroundColor Gray
        Write-Host '         Mostra este resultado a Staff para validacao. Amarelo nao e reprovacao automatica.' -ForegroundColor Gray
    }
    else {
        Write-Host '  [ OK ]  TODOS OS REQUISITOS FORAM CONFIRMADOS' -ForegroundColor Green
        Write-Host '         O computador esta pronto para a verificacao da Staff.' -ForegroundColor Gray
    }

    # Nota de contexto
    Write-Host ''
    Write-Host ('  ' + ('-' * 72)) -ForegroundColor DarkGray
    Write-Host '  IMPORTANTE' -ForegroundColor White
    Write-Host '  Este programa e apenas um PRE-CHECK de configuracoes do Windows.' -ForegroundColor DarkGray
    Write-Host '  Nao deteta cheats, nao analisa ficheiros e nao substitui o PC Check da Staff.' -ForegroundColor DarkGray
    Write-Host '  O script apenas consulta informacoes; nao altera configuracoes do computador.' -ForegroundColor DarkGray
    Write-Host ('  ' + ('-' * 72)) -ForegroundColor DarkGray
    Write-Host '  [R] Atualizar verificacao                         [Q] Sair' -ForegroundColor White
    Write-Host ''
}

while ($true) {
    Show-PreCheck

    $choice = Read-Host '  Opcao'
    if ($choice -match '^[qQ]$') {
        break
    }
    if ($choice -match '^[rR]$') {
        continue
    }

    Write-Host '  Opcao invalida. Utiliza R para atualizar ou Q para sair.' -ForegroundColor Yellow
    [void](Read-Host '  Carrega em ENTER para continuar')
}
