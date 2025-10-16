<#
.SYNOPSIS
    Erzeugt ein sicheres Passwort, zeigt es an, kopiert es in die Zwischenablage
    und protokolliert den SHA256-Hash, um Duplikate zu vermeiden.

.DESCRIPTION
    - Log: %APPDATA%\pwgen\pw_hashes.txt (Format: ISO8601|hash)
    - Es werden keine Klartext-Passwörter gespeichert.
    - Falls das Skript nicht im STA-Modus läuft, startet es sich selbst mit -STA neu.
#>

param (
    [int]$Length = 16,
    [string]$Chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?',
    [int]$MaxAttempts = 1000
)

# --- STA-Re-Launch (für Clipboard / MessageBox) ---
if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne 'STA') {
    if ($PSCommandPath) {
        Write-Verbose "Nicht im STA-Modus - starte PowerShell erneut mit -STA..."
        $args = @("-NoProfile","-Sta","-ExecutionPolicy","Bypass","-File", "`"$PSCommandPath`"")
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = (Get-Command powershell.exe).Source
        $psi.Arguments = $args -join ' '
        $psi.UseShellExecute = $true
        $proc = [System.Diagnostics.Process]::Start($psi)
        $proc.WaitForExit()
        exit $proc.ExitCode
    } else {
        Write-Error "Kann das Skript nicht erneut im STA-Modus starten (unbekannter Pfad). Bitte starte PowerShell mit -STA."
        exit 1
    }
}

try {
    # --- Vorbereitungen ---
    $logDir = Join-Path $env:APPDATA 'pwgen'
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logFile = Join-Path $logDir 'pw_hashes.txt'

    # Charset absichern (kein leeres Charset)
    if ([string]::IsNullOrEmpty($Chars)) {
        throw "Kein Zeichen-Set angegeben."
    }

    # RNG & SHA-Objekte
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $sha = [System.Security.Cryptography.SHA256]::Create()

    $attempt = 0
    $pw = $null
    $hashHex = $null

    while ($true) {
        $attempt++
        if ($attempt -gt $MaxAttempts) { throw "Maximale Anzahl an Versuchen ($MaxAttempts) erreicht." }

        # zufällige bytes erzeugen
        $bytes = New-Object byte[] $Length
        $rng.GetBytes($bytes)

        # map bytes -> Zeichen
        $charsArr = $Chars.ToCharArray()
        $charsLen = $charsArr.Length
        $pwChars = for ($i=0; $i -lt $Length; $i++) { $charsArr[ $bytes[$i] % $charsLen ] }
        $pw = -join $pwChars

        # hash berechnen
        $hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($pw))
        $hashHex = ([System.BitConverter]::ToString($hashBytes)).Replace('-','').ToLower()

        # prüfen ob Hash bereits im Log steht
        $exists = $false
        if (Test-Path $logFile) {
            # schnelle Prüfung: Zeile enthält Hash
            $exists = Select-String -Path $logFile -Pattern $hashHex -SimpleMatch -Quiet
        }

        if (-not $exists) {
            # eintragen und beenden
            $timestamp = (Get-Date).ToString('o')
            "$timestamp|$hashHex" | Out-File -FilePath $logFile -Encoding utf8 -Append
            break
        } else {
            # wenn Duplikat, nochmal versuchen
            Start-Sleep -Milliseconds 10
            continue
        }
    }

    # --- Zwischenablage-Fallbacks ---
    $copied = $false
    try {
        if (Get-Command -Name Set-Clipboard -ErrorAction SilentlyContinue) {
            Set-Clipboard -Value $pw
            $copied = $true
        }
    } catch {}

    if (-not $copied) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.Clipboard]::SetText($pw)
            $copied = $true
        } catch {}
    }

    if (-not $copied) {
        try {
            # clip.exe Fallback
            $pw | clip.exe
            $copied = $true
        } catch {}
    }

    # --- Dialog-Fallbacks ---
    $dialogShown = $false
    $info = "Generiertes Passwort:`n`n$pw`n`n(Log: $logFile)"
    if ($copied) { $info += "`n(Das Passwort wurde in die Zwischenablage kopiert.)" }
    else { $info += "`n(Hinweis: Konnte nicht in die Zwischenablage kopiert werden.)" }

    # Try WPF MessageBox first
    try {
        Add-Type -AssemblyName PresentationFramework
        [System.Windows.MessageBox]::Show($info, "Sicheres Passwort", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        $dialogShown = $true
    } catch {}

    if (-not $dialogShown) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show($info, "Sicheres Passwort", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            $dialogShown = $true
        } catch {}
    }

    # Fallback: mshta alert
    if (-not $dialogShown) {
        try {
            $escaped = $info -replace '"','\"' -replace "`n","&#10;"
            Start-Process -FilePath "mshta.exe" -ArgumentList ("javascript:alert(`"" + $escaped + "`");close()") -WindowStyle Hidden
            $dialogShown = $true
        } catch {}
    }

    # Konsole ausgeben (nützlich wenn per CLI gestartet)
    Write-Host "Passwort: $pw"
    Write-Host "Hash (SHA256): $hashHex"
    Write-Host "Log-Datei: $logFile"
    if ($copied) { Write-Host "(In Zwischenablage kopiert)"; } else { Write-Host "(Zwischenablage nicht verfügbar)"; }

    exit 0
}
catch {
    Write-Error "Fehler: $_"
    exit 2
}
finally {
    if ($rng) { $rng.Dispose() }
    if ($sha) { $sha.Dispose() }
}
