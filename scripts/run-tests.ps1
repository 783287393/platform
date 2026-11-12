# 运行全部自动测试并把结果写入 docs\evidence\test-run.txt，同时导出复核记录与报告哈希
$root = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path -LiteralPath $venvPython) { $python = $venvPython } else { $python = "python" }

$evidenceDir = Join-Path $root "docs\evidence"
New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
$logFile = Join-Path $evidenceDir "test-run.txt"

$env:PYTHONIOENCODING = "utf-8"
$report = New-Object System.Collections.Generic.List[string]
$report.Add("===== 自动测试运行 " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss") + " =====")
$report.Add("Python " + (& $python --version 2>&1))

Push-Location $root
$pytestOutput = & $python -m pytest tests -q 2>&1
$pytestExit = $LASTEXITCODE
Pop-Location
$report.Add("")
$report.Add("--- pytest：范围门禁 / 解析去重 / 工作流 / 回归 / 复扫对比 ---")
$report.Add(($pytestOutput | Out-String).Trim())
$report.Add("pytest 退出码：" + $pytestExit)

# 导出复核记录与前后报告哈希
Push-Location $root
& $python -m core.evidence
Pop-Location

$report -join "`r`n" | Out-File -LiteralPath $logFile -Encoding utf8
Write-Host "测试结果已写入 docs\evidence\test-run.txt"

if ($pytestExit -ne 0) {
    Write-Warning "存在失败用例，请查看 docs\evidence\test-run.txt"
    exit 1
}
