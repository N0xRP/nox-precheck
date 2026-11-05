#requires -Version 5.1
# ==============================================================================
# NOX RP - Security & Service Integrity PRE-CHECK
# Desenvolvido por: Nev3rFlame
# Versao: 2.0
#
# Esta ferramenta e apenas um pre-check informativo e de leitura.
# Nao altera servicos, registo, politicas, ficheiros ou configuracoes do Windows.
# Nao deteta cheats e nao substitui o PC Check realizado pela Staff.
# ==============================================================================

$ServerName = 'NOX RP'
$Author = 'Nev3rFlame'
$ScriptVersion = '2.0'

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
    $Host.UI.RawUI.WindowTitle = "$ServerName | Security Guard $ScriptVersion - by $Author"
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

function Show-PreCheck {
    try { Clear-Host } catch { }

    $now = Get-Date
    $os = $null
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

    Write-Host ('=' * 78) -ForegroundColor Magenta
    Write-Host ("                 {0} - PRE-CHECK DE SISTEMA" -f $ServerName) -ForegroundColor Cyan
    Write-Host ("                    Desenvolvido por: {0} | Versao {1}" -f $Author, $ScriptVersion) -ForegroundColor DarkCyan
    Write-Host ('=' * 78) -ForegroundColor Magenta
    Write-Host (" Windows: {0} | Build: {1}" -f $os.Caption, $os.BuildNumber) -ForegroundColor Gray
    Write-Host (" Agora: {0:dd/MM/yyyy HH:mm:ss} | Ligado ha: {1}" -f $now, (Format-Duration $uptime)) -ForegroundColor Gray

    Write-Host ''
    Write-Host '[1] AUDITORIA DE SERVICOS' -ForegroundColor Cyan
    Write-Host (' {0,-4} {1,-14} {2,-14} {3}' -f '#', 'Servico', 'Estado', 'Detalhe') -ForegroundColor DarkGray
    Write-Host (' ' + ('-' * 74)) -ForegroundColor DarkGray

    $index = 1
    foreach ($result in $serviceResults) {
        $color = Get-StatusColor -Code $result.Code
        Write-Host (' [{0}] ' -f $index) -NoNewline -ForegroundColor DarkGray
        Write-Host ('{0,-14} ' -f $result.Name) -NoNewline
        Write-Host ('{0,-14} ' -f $result.Status) -NoNewline -ForegroundColor $color
        Write-Host $result.Detail -ForegroundColor Gray
        $index++
    }

    Write-Host ''
    Write-Host '[2] SEGURANCA DO WINDOWS' -ForegroundColor Cyan
    Write-Host (' {0,-4} {1,-48} {2}' -f '#', 'Componente', 'Estado') -ForegroundColor DarkGray
    Write-Host (' ' + ('-' * 74)) -ForegroundColor DarkGray

    $letterCode = 65
    foreach ($result in $securityResults) {
        $color = Get-StatusColor -Code $result.Code
        Write-Host (' [{0}] ' -f [char]$letterCode) -NoNewline -ForegroundColor DarkGray
        Write-Host ('{0,-48} ' -f $result.Name) -NoNewline
        Write-Host $result.Status -ForegroundColor $color
        Write-Host ('     {0}' -f $result.Detail) -ForegroundColor Gray
        $letterCode++
    }

    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Magenta
    Write-Host (" Resumo: {0} confirmados | {1} pendentes | {2} requisitos em falta" -f `
        $passedCount, $pendingCount, $failedCount) -ForegroundColor White

    if ($failedCount -gt 0) {
        Write-Host (" RESULTADO: NAO CONFORME COM OS REQUISITOS DO PRE-CHECK DO {0}" -f $ServerName) -ForegroundColor Red
        Write-Host ' -> Consulta os itens a vermelho e segue as instrucoes oficiais do servidor.' -ForegroundColor Yellow
    }
    elseif ($pendingCount -gt 0) {
        Write-Host ' RESULTADO: VERIFICACAO PENDENTE' -ForegroundColor Yellow
        Write-Host ' -> Existem itens que nao puderam ser confirmados. Mostra este ecra a Staff.' -ForegroundColor Yellow
        Write-Host ' -> Amarelo nao significa, por si so, que o computador esteja reprovado.' -ForegroundColor Gray
    }
    else {
        Write-Host (" RESULTADO: TODOS OS REQUISITOS VERIFICADOS - {0}" -f $ServerName) -ForegroundColor Green
    }

    Write-Host ''
    Write-Host ' NOTA: Este e apenas um pre-check de configuracoes do Windows.' -ForegroundColor Gray
    Write-Host ' Nao procura cheats, nao analisa ficheiros e nao substitui o PC Check da Staff.' -ForegroundColor Gray
    Write-Host ' O script apenas consulta informacoes; nao altera configuracoes do computador.' -ForegroundColor Gray
    Write-Host ('=' * 78) -ForegroundColor Magenta
    Write-Host ' [R] Atualizar     [Q] Sair' -ForegroundColor White
}

while ($true) {
    Show-PreCheck

    $choice = Read-Host 'Opcao'
    if ($choice -match '^[qQ]$') {
        break
    }
    if ($choice -match '^[rR]$') {
        continue
    }

    Write-Host 'Opcao invalida. Utiliza R para atualizar ou Q para sair.' -ForegroundColor Yellow
    [void](Read-Host 'Carrega em ENTER para continuar')
}
