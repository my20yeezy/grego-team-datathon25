
# Генерируем и отправляем случайные логи
function Send-RandomLog {
    param([string]$url)
    $logTypes = @("cowrie_ssh", "palo_alto_firewall", "fortinet_firewall", "generic_syslog")
    $severities = @("low", "medium", "high", "critical")
    $log = @{
        event_id = [guid]::NewGuid().ToString()
        timestamp = (Get-Date).ToString('o')
        log_type = $logTypes | Get-Random
        source = "192.168.1.$((Get-Random -Minimum 1 -Maximum 255))"
        severity = $severities | Get-Random
        raw_data = @{ msg = "Random test log $(Get-Random)" }
    } | ConvertTo-Json
    try {
        $resp = Invoke-RestMethod -Uri $url -Method Post -Body $log -ContentType "application/json" -ErrorAction Stop
        Write-Host "Sent log: $($log)" -ForegroundColor Cyan
    } catch {
        Write-Host "Error sending log: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 1. Проверяем доступность API
$healthUrl = "http://localhost:8000/health"
try {
    $response = Invoke-WebRequest -Uri $healthUrl -UseBasicParsing -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "API server is running and accessible." -ForegroundColor Green
    } else {
        Write-Host "API server returned an unexpected status code: $($response.StatusCode)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "API server is not accessible. Error: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 2. Отправляем 5 случайных логов
$logUrl = "http://localhost:8000/api/v1/logs"
for ($i=0; $i -lt 5; $i++) {
    Send-RandomLog -url $logUrl
    Start-Sleep -Milliseconds 500
}

# 3. Проверяем наличие аномалий
$anomalyStatsUrl = "http://localhost:8000/api/v1/anomalies/stats"
$anomalySearchUrl = "http://localhost:8000/api/v1/anomalies/search"

try {
    $stats = Invoke-RestMethod -Uri $anomalyStatsUrl -ErrorAction Stop
    Write-Host "Anomaly stats:" -ForegroundColor Yellow
    $stats | ConvertTo-Json | Write-Host
} catch {
    Write-Host "Error getting anomaly stats: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    $anomalies = Invoke-RestMethod -Uri $anomalySearchUrl -ErrorAction Stop
    Write-Host "Anomalies found:" -ForegroundColor Yellow
    $anomalies | ConvertTo-Json | Write-Host
    if ($anomalies.Count -gt 0) {
        Write-Host "Anomalies detected!" -ForegroundColor Magenta
    } else {
        Write-Host "No anomalies detected." -ForegroundColor Green
    }
} catch {
    Write-Host "Error getting anomalies: $($_.Exception.Message)" -ForegroundColor Red
}
