# SwitchGuard Lab Orchestrator
# This script verifies VirtualBox VM connectivity and prepares the environment for a hybrid scan.

$VM_NAME = "Metasploitable2" # Change to your VM name
$TARGET_IP = "192.168.56.101" # Host-only adapter IP

Write-Host "--- SwitchGuard Lab Setup ---" -ForegroundColor Yellow

# 1. Check if VirtualBox is in PATH
if (!(Get-Command VBoxManage -ErrorAction SilentlyContinue)) {
    Write-Error "VBoxManage not found. Please ensure VirtualBox is installed and in your PATH."
    exit 1
}

# 2. Check VM Status
$vmStatus = VBoxManage showvminfo $VM_NAME --machinereadable | Select-String "VMState="
if ($vmStatus -match "running") {
    Write-Host "[OK] VM '$VM_NAME' is already running." -ForegroundColor Green
} else {
    Write-Host "[!] VM '$VM_NAME' is not running. Starting..." -ForegroundColor Cyan
    VBoxManage startvm $VM_NAME --type headless
    Start-Sleep -Seconds 30 # Wait for boot
}

# 3. Verify Connectivity
Write-Host "[*] Pinging target $TARGET_IP ..."
if (Test-Connection -ComputerName $TARGET_IP -Count 2 -Quiet) {
    Write-Host "[OK] Target is reachable." -ForegroundColor Green
} else {
    Write-Warning "Target is not responding to ping. Check Host-Only network settings."
}

# 4. Baseline Port Check
Write-Host "[*] Running baseline Nmap check..." -ForegroundColor Gray
& nmap -F $TARGET_IP

Write-Host "`n--- Readiness Check Complete ---" -ForegroundColor Green
Write-Host "You can now launch a 'Hybrid Scan' from the SwitchGuard Dashboard targeting $TARGET_IP."
