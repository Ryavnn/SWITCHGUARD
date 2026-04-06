# ZAP Startup Script for Windows
$zapPath = "C:\Program Files\ZAP\Zed Attack Proxy\zap-2.17.0.jar"
$apiKey = "12345"
$port = "8080"

Write-Host "Starting OWASP ZAP in daemon mode on port $port..." -ForegroundColor Cyan

Start-Process java -ArgumentList "-Xmx512m", "-jar", "`"$zapPath`"", "-daemon", "-port", "$port", "-config", "api.key=$apiKey", "-config", "api.addrs.addr.name=.*", "-config", "api.addrs.addr.regex=true" -RedirectStandardOutput "zap_stdout.log" -RedirectStandardError "zap_stderr.log" -NoNewWindow
