# ==============================================================================
# NOX RP - Security & Service Integrity Verifier (Protected Build)
# Desenvolvido em exclusivo por: Nev3rFlame
# ==============================================================================

$_0x01 = -join [char[]]@(0x4E,0x4F,0x58,0x20,0x52,0x50)
$_0x02 = -join [char[]]@(0x4E,0x65,0x76,0x33,0x72,0x46,0x6C,0x61,0x6D,0x65)

$Host.UI.RawUI.WindowTitle = "$_0x01 | Security Guard - by $_0x02"

$_0x03 = @(
    (-join [char[]]@(0x50,0x63,0x61,0x53,0x76,0x63)),
    (-join [char[]]@(0x44,0x50,0x53)),
    (-join [char[]]@(0x44,0x69,0x61,0x67,0x54,0x72,0x61,0x63,0x6B)),
    (-join [char[]]@(0x45,0x76,0x65,0x6E,0x74,0x4C,0x6F,0x67)),
    (-join [char[]]@(0x53,0x79,0x73,0x4D,0x61,0x69,0x6E)),
    (-join [char[]]@(0x53,0x63,0x68,0x65,0x64,0x75,0x6C,0x65)),
    (-join [char[]]@(0x44,0x75,0x73,0x6D,0x53,0x76,0x63)),
    (-join [char[]]@(0x41,0x70,0x70,0x69,0x6E,0x66,0x6F)),
    (-join [char[]]@(0x57,0x53,0x65,0x61,0x72,0x63,0x68))
)

function _0xF1([TimeSpan]$_t) {
    if ($_t.TotalDays -ge 1) { return ('{0}d {1}h' -f [int][Math]::Floor($_t.TotalDays), $_t.Hours) }
    if ($_t.TotalHours -ge 1) { return ('{0}h {1:D2}m' -f [int][Math]::Floor($_t.TotalHours), $_t.Minutes) }
    return ('{0}m' -f [int][Math]::Floor($_t.TotalMinutes))
}

function _0xF2([DateTime]$_b, [DateTime]$_n) {
    $_f = ($_0x03 | ForEach-Object { "Name='$_'" }) -join ' OR '
    $_found = @{}
    Get-CimInstance -ClassName Win32_Service -Filter $_f -ErrorAction SilentlyContinue | ForEach-Object { $_found[$_.Name] = $_ }

    $_started = @{}
    $_pids = @($_found.Values | Where-Object { $_.ProcessId -gt 0 } | ForEach-Object { $_.ProcessId } | Sort-Object -Unique)
    if ($_pids.Count -gt 0) {
        $_pf = ($_pids | ForEach-Object { "ProcessId=$_" }) -join ' OR '
        Get-CimInstance -ClassName Win32_Process -Filter $_pf -ErrorAction SilentlyContinue | ForEach-Object {
            $_started[[uint32]$_.ProcessId] = $_.CreationDate
        }
    }

    foreach ($_k in $_0x03) {
        $_s = $_found[$_k]
        if (-not $_s) {
            [pscustomobject]@{ N = $_k; S = 'INEXISTENTE'; M = '-'; U = '-'; C = 12; K = 2 }
            continue
        }

        $_run = ($_s.State -eq (-join [char[]]@(0x52,0x75,0x6E,0x6E,0x69,0x6E,0x67)))
        $_ok  = ($_run -and ($_s.StartMode -ne (-join [char[]]@(0x44,0x69,0x73,0x61,0x62,0x6C,0x65,0x64))))
        $_c   = if ($_ok) { 10 } else { 12 }
        $_st  = if ($_ok) { 0 } else { 2 }
        $_sl  = if ($_run) { 'OK' } else { 'PARADO' }
        $_md  = switch ($_s.StartMode) { 'Auto' { 'Automatico' } 'Manual' { 'Manual' } 'Disabled' { 'Desativado' } default { $_s.StartMode } }
        $_up  = '-'

        if ($_run) {
            $_ps = $_started[[uint32]$_s.ProcessId]
            if (-not $_ps) {
                $_up = '?'
            } elseif (($_ps - $_b).TotalMinutes -gt 5) {
                $_up = '{0:HH:mm} (iniciado ha {1})' -f $_ps, (_0xF1 ($_n - $_ps))
                if ($_st -eq 0) { $_st = 1; $_c = 14 }
            } else {
                $_up = 'Desde o arranque'
            }
        }

        [pscustomobject]@{ N = $_k; S = $_sl; M = $_md; U = $_up; C = $_c; K = $_st }
    }
}

function _0xF3 {
    $_q = @(
        @{ L = 'Isolamento de Nucleos (Integridade da Memoria)'; E = {
            (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop).SecurityServicesRunning -contains 2
        } },
        @{ L = 'Blocklist de Drivers Vulneraveis da Microsoft'; E = {
            $_v = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction Stop).VulnerableDriverBlocklistEnable
            ($null -eq $_v) -or ($_v -eq 1)
        } },
        @{ L = 'Arranque Seguro UEFI (Secure Boot)'; E = {
            (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled -eq 1
        } },
        @{ L = 'Modulo de Plataforma Fidedigna (TPM 2.0)'; E = {
            $_t = Get-CimInstance -ClassName Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" -ErrorAction Stop |
                  Where-Object { $_.Name -like '*Trusted Platform Module*' } | Select-Object -First 1
            [bool]$_t -and ($_t.Status -eq 'OK')
        } }
    )

    foreach ($_i in $_q) {
        try {
            if (& $_i.E) {
                [pscustomobject]@{ F = $_i.L; S = 'ATIVO'; C = 10; K = 0 }
            } else {
                [pscustomobject]@{ F = $_i.L; S = 'DESATIVADO'; C = 12; K = 2 }
            }
        } catch {
            [pscustomobject]@{ F = $_i.L; S = 'SEM LEITURA'; C = 14; K = 1 }
        }
    }
}

function _0xF4 {
    try { Clear-Host } catch { }

    $_chk1 = 0
    foreach ($_c in [char[]]$_0x01) { $_chk1 += [int][char]$_c }
    $_chk2 = 0
    foreach ($_c in [char[]]$_0x02) { $_chk2 += [int][char]$_c }

    if ($_chk1 -ne 439 -or $_chk2 -ne 947 -or $_0x01.Length -ne 6 -or $_0x02.Length -ne 10 -or $_0x03.Count -ne 9) {
        Write-Host "[ERRO CRITICO] Assinatura do autor ou codigo adulterados! Execucao bloqueada." -ForegroundColor Red
        return
    }

    $_os = Get-CimInstance -ClassName Win32_OperatingSystem
    $_bt = $_os.LastBootUpTime
    $_nw = Get-Date
    $_sv = @(_0xF2 $_bt $_nw)
    $_sc = @(_0xF3)

    Write-Host ("=" * 70) -ForegroundColor ([ConsoleColor]5)
    Write-Host ("                    $_0x01 - VERIFICACAO DE SISTEMA                   ") -ForegroundColor ([ConsoleColor]13)
    Write-Host ("                     Desenvolvido por: $_0x02                     ") -ForegroundColor ([ConsoleColor]11)
    Write-Host ("=" * 70) -ForegroundColor ([ConsoleColor]5)
    Write-Host (" Agora: {0:dd/MM/yyyy HH:mm:ss}   |   Windows ligado desde: {1:dd/MM HH:mm} (ha {2})" -f $_nw, $_bt, (_0xF1 ($_nw - $_bt))) -ForegroundColor ([ConsoleColor]7)
    Write-Host ""
    Write-Host " [1] AUDITORIA DE SERVICOS" -ForegroundColor ([ConsoleColor]11)
    Write-Host (" {0,-4} {1,-12} {2,-12} {3,-14} {4}" -f '#', 'Servico', 'Estado', 'Arranque', 'A correr desde') -ForegroundColor ([ConsoleColor]8)
    Write-Host (" " + ("-" * 68)) -ForegroundColor ([ConsoleColor]8)

    $_x = 1
    foreach ($_r in $_sv) {
        Write-Host (" {0,-4} {1,-12} " -f "[$_x]", $_r.N) -NoNewline
        Write-Host ("{0,-12} " -f $_r.S) -ForegroundColor ([ConsoleColor]$_r.C) -NoNewline
        Write-Host ("{0,-14} " -f $_r.M) -NoNewline
        Write-Host $_r.U -ForegroundColor ([ConsoleColor]$_r.C)
        $_x++
    }

    Write-Host ""
    Write-Host " [2] SEGURANCA DO WINDOWS" -ForegroundColor ([ConsoleColor]11)
    Write-Host (" {0,-4} {1,-50} {2}" -f '#', 'Componente', 'Estado') -ForegroundColor ([ConsoleColor]8)
    Write-Host (" " + ("-" * 68)) -ForegroundColor ([ConsoleColor]8)

    $_ch = 65
    foreach ($_s in $_sc) {
        $_lt = '[{0}]' -f [char]$_ch
        Write-Host (" {0,-4} {1,-50} " -f $_lt, $_s.F) -NoNewline
        Write-Host $_s.S -ForegroundColor ([ConsoleColor]$_s.C)
        $_ch++
    }

    Write-Host ("=" * 70) -ForegroundColor ([ConsoleColor]5)
    $_bd = @($_sv + $_sc | Where-Object { $_.K -eq 2 }).Count
    $_lt = @($_sv | Where-Object { $_.K -eq 1 }).Count
    $_un = @($_sc | Where-Object { $_.K -eq 1 }).Count

    if ($_bd -gt 0) {
        Write-Host (" NAO estas OK para jogar no $_0x01 ($_bd falha(s) detetada(s))") -ForegroundColor ([ConsoleColor]12)
        Write-Host " -> Servicos: abre services.msc, mete em Automatico e inicia." -ForegroundColor ([ConsoleColor]14)
        Write-Host " -> Seguranca: abre Seguranca do Windows, ativa o que falta e reinicia." -ForegroundColor ([ConsoleColor]14)
    } elseif ($_lt -gt 0) {
        Write-Host (" Tudo a correr, mas $_lt servico(s) iniciado(s) depois do arranque.") -ForegroundColor ([ConsoleColor]14)
        Write-Host " -> Nao e chumbo. Mostra este ecra a Staff do $_0x01." -ForegroundColor ([ConsoleColor]7)
    } else {
        Write-Host (" Estas OK para jogar no $_0x01!") -ForegroundColor ([ConsoleColor]10)
    }

    if ($_un -gt 0) {
        Write-Host (" Nota: $_un funcao(oes) de seguranca requer(em) confirmacao manual pela Staff.") -ForegroundColor ([ConsoleColor]14)
    }

    Write-Host ""
    Write-Host (" [R] Atualizar     [Q] Sair                    [Script by $_0x02]") -ForegroundColor ([ConsoleColor]15)
}

while ($true) {
    _0xF4
    try { $_op = Read-Host 'Opcao' } catch { break }
    if ($_op -match '^[qQ]$') { break }
}
