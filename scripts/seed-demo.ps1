# 重置并写入演示样本数据（清空 data/security.db，导入 before/after 样本与复核记录）
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) { $python = "python" }

Push-Location $root
& $python -m core.seed
& $python -m core.evidence
Pop-Location
Write-Host "演示数据已重新初始化。"
